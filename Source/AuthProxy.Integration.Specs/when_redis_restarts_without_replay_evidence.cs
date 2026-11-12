// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.BearerRoutes.Dpop;

namespace Cratis.AuthProxy.Integration.Specs;

/// <summary>Exercises loss of replay evidence during a real Redis restart.</summary>
/// <param name="redis">The shared Redis process.</param>
[Collection(RedisReplayCollection.Name)]
public class when_redis_restarts_without_replay_evidence(RedisReplayFixture redis) : given_a_redis_replay_store(redis)
{
    /// <summary>Old and new replicas fail closed until full coverage is restored.</summary>
    /// <returns>The scenario operation.</returns>
    [Fact]
    public async Task should_quarantine_restarted_redis_instead_of_reusing_cached_health()
    {
        await SeedCoverage(TimeSpan.FromSeconds(391));
        var warmed = Replica();
        (await warmed.CheckHealth(CancellationToken.None)).ShouldEqual(DpopReplayResult.Accepted);
        (await Consume(warmed)).ShouldEqual(DpopReplayResult.Accepted);
        await Redis.Restart();
        (await Database.KeyExistsAsync(CoverageKey)).ShouldBeFalse();
        (await Database.KeyExistsAsync(ReplayKey("synthetic-proof"))).ShouldBeFalse();
        (await Consume(warmed)).ShouldEqual(DpopReplayResult.Unavailable);
        var restarted = Replica();
        (await restarted.CheckHealth(CancellationToken.None)).ShouldEqual(DpopReplayResult.Unavailable);
        (await Consume(restarted)).ShouldEqual(DpopReplayResult.Unavailable);
        await SeedCoverage(TimeSpan.FromSeconds(391));
        (await Consume(restarted)).ShouldEqual(DpopReplayResult.Accepted);
    }
}
