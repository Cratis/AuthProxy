// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.BearerRoutes.Dpop;

namespace Cratis.AuthProxy.Integration.Specs;

/// <summary>Exercises Redis TIME checks independently of coverage readiness.</summary>
/// <param name="redis">The shared Redis process.</param>
[Collection(RedisReplayCollection.Name)]
public class when_a_replica_clock_disagrees_with_redis(RedisReplayFixture redis) : given_a_redis_replay_store(redis)
{
    /// <summary>Skew beyond thirty seconds refuses health and reservation without evidence.</summary>
    /// <param name="seconds">The clock offset in seconds.</param>
    /// <returns>The scenario operation.</returns>
    [Theory]
    [InlineData(31)]
    [InlineData(-31)]
    public async Task should_refuse_health_and_reservation_outside_thirty_seconds(int seconds)
    {
        await SeedCoverage(TimeSpan.FromSeconds(391));
        var store = Replica(new OffsetClock(seconds));
        (await store.CheckHealth(CancellationToken.None)).ShouldEqual(DpopReplayResult.Unavailable);
        (await Consume(store)).ShouldEqual(DpopReplayResult.Unavailable);
        (await Database.KeyExistsAsync(ReplayKey("synthetic-proof"))).ShouldBeFalse();
    }

    /// <summary>A reservation rechecks skew even when cached health remains ready.</summary>
    /// <returns>The scenario operation.</returns>
    [Fact]
    public async Task should_check_clock_skew_again_despite_cached_health()
    {
        await SeedCoverage(TimeSpan.FromSeconds(391));
        var clock = new OffsetClock(0);
        var store = Replica(clock);
        (await store.CheckHealth(CancellationToken.None)).ShouldEqual(DpopReplayResult.Accepted);
        clock.Seconds = 31;
        (await store.CheckHealth(CancellationToken.None)).ShouldEqual(DpopReplayResult.Accepted);
        (await Consume(store)).ShouldEqual(DpopReplayResult.Unavailable);
    }

    sealed class OffsetClock(int seconds) : TimeProvider
    {
        public int Seconds { get; set; } = seconds;
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.UtcNow.AddSeconds(Seconds);
    }
}
