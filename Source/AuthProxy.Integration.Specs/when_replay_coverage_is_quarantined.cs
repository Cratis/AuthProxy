// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.BearerRoutes.Dpop;

namespace Cratis.AuthProxy.Integration.Specs;

/// <summary>Exercises coverage quarantine on the real Redis script.</summary>
/// <param name="redis">The shared Redis process.</param>
[Collection(RedisReplayCollection.Name)]
public class when_replay_coverage_is_quarantined(RedisReplayFixture redis) : given_a_redis_replay_store(redis)
{
    /// <summary>Reservations require a known full replay-retention window.</summary>
    /// <returns>The scenario operation.</returns>
    [Fact]
    public async Task should_refuse_missing_and_young_coverage_until_a_full_retention_window_is_known()
    {
        var store = Replica();
        (await store.CheckHealth(CancellationToken.None)).ShouldEqual(DpopReplayResult.Unavailable);
        (await Database.KeyExistsAsync(CoverageKey)).ShouldBeTrue();
        (await Consume(store)).ShouldEqual(DpopReplayResult.Unavailable);
        await SeedCoverage(TimeSpan.FromSeconds(380));
        (await Consume(store)).ShouldEqual(DpopReplayResult.Unavailable);
        await SeedCoverage(TimeSpan.FromSeconds(391));
        (await Consume(store)).ShouldEqual(DpopReplayResult.Accepted);
    }

    /// <summary>Cached readiness never bypasses the atomic coverage check.</summary>
    /// <returns>The scenario operation.</returns>
    [Fact]
    public async Task should_not_let_cached_ready_health_bypass_lost_coverage()
    {
        await SeedCoverage(TimeSpan.FromSeconds(391));
        var store = Replica();
        (await store.CheckHealth(CancellationToken.None)).ShouldEqual(DpopReplayResult.Accepted);
        await Database.KeyDeleteAsync(CoverageKey);
        (await store.CheckHealth(CancellationToken.None)).ShouldEqual(DpopReplayResult.Accepted);
        (await Consume(store)).ShouldEqual(DpopReplayResult.Unavailable);
        (await Database.KeyExistsAsync(ReplayKey("synthetic-proof"))).ShouldBeFalse();
    }
}
