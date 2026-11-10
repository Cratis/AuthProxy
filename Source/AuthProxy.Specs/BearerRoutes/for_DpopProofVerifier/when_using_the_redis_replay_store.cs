// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.BearerRoutes.Dpop;
using StackExchange.Redis;

namespace Cratis.AuthProxy.BearerRoutes.for_DpopProofVerifier;

public class when_using_the_redis_replay_store : given_a_dpop_gate
{
    IDatabase _database;
    RedisDpopReplayStore _store;

    void Establish()
    {
        Options.Dpop.ReplayStore.Redis = new() { ConnectionString = "replay.example.test:6379", KeyPrefix = "synthetic-deployment" };
        _database = Substitute.For<IDatabase>();
        _database.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>(), Arg.Any<CommandFlags>()).Returns(Result(1));
        _store = new(Microsoft.Extensions.Options.Options.Create(Options), Clock, _database);
    }

    void Destroy() => _store.Dispose();

    static RedisResult Result(int status) => RedisResult.Create([RedisResult.Create((RedisValue)status), RedisResult.Create((RedisValue)(Now * 1000))]);
    Task<DpopReplayResult> Consume(string jti = "synthetic-id") => _store.TryConsume("https://api.example.test", Jkt, jti, CancellationToken.None);

    [Theory]
    [InlineData(-31, DpopReplayResult.Unavailable)]
    [InlineData(31, DpopReplayResult.Unavailable)]
    [InlineData(-30, DpopReplayResult.Accepted)]
    [InlineData(30, DpopReplayResult.Accepted)]
    public async Task should_enforce_the_thirty_second_clock_bound(long offset, DpopReplayResult expected)
    {
        Clock.Seconds += offset;
        (await _store.CheckHealth(CancellationToken.None)).ShouldEqual(expected);
        (await Consume()).ShouldEqual(expected);
        await _database.Received(2).ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>(), Arg.Any<CommandFlags>());
    }

    [Theory]
    [InlineData(2, DpopReplayResult.Replay)]
    [InlineData(3, DpopReplayResult.Unavailable)]
    public async Task should_honor_shared_replay_and_coverage_verdicts(int status, DpopReplayResult expected)
    {
        _database.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>(), Arg.Any<CommandFlags>()).Returns(Result(status));
        (await Consume()).ShouldEqual(expected);
    }

    [Fact]
    public async Task should_use_an_atomic_bounded_hashed_key_without_raw_identifiers()
    {
        const string jti = "synthetic-proof-identifier";
        (await Consume(jti)).ShouldEqual(DpopReplayResult.Accepted);
        var call = _database.ReceivedCalls().Single();
        var keys = (RedisKey[])call.GetArguments()[1]!;
        keys.Length.ShouldEqual(2);
        keys.All(key => !key.ToString().Contains(Jkt, StringComparison.Ordinal) && !key.ToString().Contains(jti, StringComparison.Ordinal)).ShouldBeTrue();
        keys.All(key => key.ToString().Contains("{synthetic-deployment}", StringComparison.Ordinal)).ShouldBeTrue();
        keys[1].ToString().Length.ShouldBeLessThan(100);
    }

    [Fact]
    public async Task should_not_fall_back_when_redis_is_unavailable()
    {
        _database.ScriptEvaluateAsync(Arg.Any<string>(), Arg.Any<RedisKey[]>(), Arg.Any<RedisValue[]>(), Arg.Any<CommandFlags>())
            .Returns(_ => Task.FromException<RedisResult>(new RedisConnectionException(ConnectionFailureType.UnableToConnect, "synthetic-unavailable")));
        (await _store.CheckHealth(CancellationToken.None)).ShouldEqual(DpopReplayResult.Unavailable);
        (await Consume()).ShouldEqual(DpopReplayResult.Unavailable);
    }
}
