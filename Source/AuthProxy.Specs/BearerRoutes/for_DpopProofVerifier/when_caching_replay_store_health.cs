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

    [Theory]
    [InlineData(false, 10, 0)]
    [InlineData(true, 10, 0)]
    [InlineData(false, 0, 31)]
    [InlineData(true, 0, 31)]
    [InlineData(false, 0, -31)]
    [InlineData(true, 0, -31)]
    public async Task should_refuse_replies_that_arrive_after_the_clock_or_freshness_boundary(bool reservation, int elapsed, int offset)
    {
        var database = Substitute.For<IDatabase>();
        var clock = new ManualClock();
        var reply = new TaskCompletionSource<RedisResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        database.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>(), Arg.Any<CommandFlags>()).Returns(reply.Task);
        using var store = CreateStore(database, clock);
        var pending = reservation
            ? store.TryConsume("https://api.example.test", "synthetic-key", "synthetic-proof", CancellationToken.None)
            : store.CheckHealth(CancellationToken.None);
        clock.Elapsed = elapsed;
        clock.Offset = offset;
        reply.SetResult(Result(1));
        (await pending).ShouldEqual(DpopReplayResult.Unavailable);
    }

    [Fact]
    public async Task should_measure_cached_health_from_the_operation_start()
    {
        var database = Substitute.For<IDatabase>();
        var clock = new ManualClock();
        var reply = new TaskCompletionSource<RedisResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        database.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>(), Arg.Any<CommandFlags>()).Returns(reply.Task);
        using var store = CreateStore(database, clock);
        var pending = store.CheckHealth(CancellationToken.None);
        clock.Elapsed = 9;
        reply.SetResult(Result(1));
        (await pending).ShouldEqual(DpopReplayResult.Accepted);
        clock.Elapsed = 10;
        database.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>(), Arg.Any<CommandFlags>()).Returns(Task.FromResult(Result(1, Now + 10)));
        (await store.CheckHealth(CancellationToken.None)).ShouldEqual(DpopReplayResult.Accepted);
        await database.Received(2).ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>(), Arg.Any<CommandFlags>());
    }

    [Theory]
    [InlineData(null, "1800000000000")]
    [InlineData("1", null)]
    [InlineData("invalid", "1800000000000")]
    [InlineData("1", "invalid")]
    [InlineData("99999999999999999999999999", "1800000000000")]
    [InlineData("1", "99999999999999999999999999")]
    public async Task should_refuse_null_or_non_numeric_reply_fields(string? status, string? serverTime)
    {
        var database = Substitute.For<IDatabase>();
        var result = RedisResult.Create([RedisResult.Create((RedisValue)status), RedisResult.Create((RedisValue)serverTime)]);
        database.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>(), Arg.Any<CommandFlags>()).Returns(Task.FromResult(result));
        using var store = CreateStore(database, new ManualClock());
        (await store.CheckHealth(CancellationToken.None)).ShouldEqual(DpopReplayResult.Unavailable);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(3)]
    public async Task should_refuse_an_unexpected_reply_shape(int length)
    {
        var database = Substitute.For<IDatabase>();
        var result = RedisResult.Create(Enumerable.Repeat(RedisResult.Create((RedisValue)1), length).ToArray());
        database.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>(), Arg.Any<CommandFlags>()).Returns(Task.FromResult(result));
        using var store = CreateStore(database, new ManualClock());
        (await store.CheckHealth(CancellationToken.None)).ShouldEqual(DpopReplayResult.Unavailable);
    }

    [Theory]
    [InlineData(0, false)]
    [InlineData(0, true)]
    [InlineData(1, false)]
    [InlineData(1, true)]
    [InlineData(2, false)]
    [InlineData(2, true)]
    public async Task should_fail_closed_on_transport_or_script_errors_and_recover(int failure, bool reservation)
    {
        var database = Substitute.For<IDatabase>();
        Exception error = failure switch
        {
            0 => new RedisConnectionException(ConnectionFailureType.UnableToConnect, "synthetic outage"),
            1 => new TimeoutException("synthetic timeout"),
            _ => new RedisServerException("synthetic script refusal"),
        };
        database.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>(), Arg.Any<CommandFlags>()).Returns(Task.FromException<RedisResult>(error));
        var clock = new ManualClock();
        using var store = CreateStore(database, clock);
        var result = reservation
            ? await store.TryConsume("https://api.example.test", "synthetic-key", "synthetic-proof", CancellationToken.None)
            : await store.CheckHealth(CancellationToken.None);
        result.ShouldEqual(DpopReplayResult.Unavailable);
        clock.Elapsed = 10;
        database.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>(), Arg.Any<CommandFlags>()).Returns(Task.FromResult(Result(1, Now + 10)));
        (await store.CheckHealth(CancellationToken.None)).ShouldEqual(DpopReplayResult.Accepted);
    }

    [Fact]
    public async Task should_recover_after_a_cancelled_probe_without_publishing_health()
    {
        var database = Substitute.For<IDatabase>();
        var reply = new TaskCompletionSource<RedisResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        database.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>(), Arg.Any<CommandFlags>()).Returns(reply.Task);
        var clock = new ManualClock();
        using var store = CreateStore(database, clock);
        using var cancellation = new CancellationTokenSource();
        var pending = store.CheckHealth(cancellation.Token);
        await cancellation.CancelAsync();
        (await pending).ShouldEqual(DpopReplayResult.Unavailable);
        reply.SetResult(Result(1));
        clock.Elapsed = 10;
        (await store.CheckHealth(CancellationToken.None)).ShouldEqual(DpopReplayResult.Accepted);
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
