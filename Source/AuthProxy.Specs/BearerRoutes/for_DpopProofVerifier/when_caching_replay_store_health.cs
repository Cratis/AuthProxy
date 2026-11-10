// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.BearerRoutes.Dpop;
using StackExchange.Redis;

namespace Cratis.AuthProxy.BearerRoutes.for_DpopProofVerifier;

public class when_caching_replay_store_health : Specification
{
    const long Now = 1800000000;

    [Theory]
    [InlineData(1, DpopReplayResult.Accepted)]
    [InlineData(0, DpopReplayResult.Unavailable)]
    public async Task should_recheck_health_only_after_ten_seconds(int status, DpopReplayResult expected)
    {
        var database = Substitute.For<IDatabase>();
        var clock = new ManualClock();
        database.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>(), Arg.Any<CommandFlags>())
            .Returns(_ => Task.FromResult(Result(status, Now + clock.Elapsed)));
        using var store = CreateStore(database, clock);
        (await store.CheckHealth(CancellationToken.None)).ShouldEqual(expected);
        clock.Elapsed = 9;
        (await store.CheckHealth(CancellationToken.None)).ShouldEqual(expected);
        clock.Elapsed = 10;
        (await store.CheckHealth(CancellationToken.None)).ShouldEqual(expected);
        await database.Received(2).ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>(), Arg.Any<CommandFlags>());
    }

    [Fact]
    public async Task should_share_the_inflight_health_check_between_concurrent_requests()
    {
        var database = Substitute.For<IDatabase>();
        var reply = new TaskCompletionSource<RedisResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        database.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>(), Arg.Any<CommandFlags>()).Returns(reply.Task);
        using var store = CreateStore(database, new ManualClock());
        var checks = Enumerable.Range(0, 24).Select(_ => store.CheckHealth(CancellationToken.None)).ToArray();
        reply.SetResult(Result(1));
        (await Task.WhenAll(checks)).All(result => result == DpopReplayResult.Accepted).ShouldBeTrue();
        await database.Received(1).ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>(), Arg.Any<CommandFlags>());
    }

    [Theory]
    [InlineData(0, 0)]
    [InlineData(1, 31)]
    public async Task should_not_let_cached_health_bypass_reservation_guards(int reservationStatus, int clockOffset)
    {
        var database = Substitute.For<IDatabase>();
        var clock = new ManualClock();
        database.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>(), Arg.Any<CommandFlags>())
            .Returns(Task.FromResult(Result(1)));
        using var store = CreateStore(database, clock);
        (await store.CheckHealth(CancellationToken.None)).ShouldEqual(DpopReplayResult.Accepted);
        clock.Offset = clockOffset;
        database.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>(), Arg.Any<CommandFlags>())
            .Returns(Task.FromResult(Result(reservationStatus)));
        (await store.CheckHealth(CancellationToken.None)).ShouldEqual(DpopReplayResult.Accepted);
        (await store.TryConsume("https://api.example.test", new string('A', 43), "synthetic-proof-identifier", CancellationToken.None)).ShouldEqual(DpopReplayResult.Unavailable);
        await database.Received(2).ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>(), Arg.Any<CommandFlags>());
    }

    static RedisResult Result(int status, long seconds = Now) => RedisResult.Create([RedisResult.Create((RedisValue)status), RedisResult.Create((RedisValue)(seconds * 1000))]);

    static RedisDpopReplayStore CreateStore(IDatabase database, TimeProvider clock)
    {
        var options = new C.AuthProxy();
        options.Dpop.ReplayStore.Redis = new() { ConnectionString = "replay.example.test:6379", KeyPrefix = "synthetic-prefix" };
        return new(Microsoft.Extensions.Options.Options.Create(options), clock, database);
    }

    sealed class ManualClock : TimeProvider
    {
        public long Elapsed { get; set; }
        public int Offset { get; set; }
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => Elapsed * TimeSpan.TicksPerSecond;
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(Now + Elapsed + Offset);
    }
}
