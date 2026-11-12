// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.BearerRoutes.Dpop;

namespace Cratis.AuthProxy.Integration.Specs;

/// <summary>Exercises atomic replay admission through independent connections.</summary>
/// <param name="redis">The shared Redis process.</param>
[Collection(RedisReplayCollection.Name)]
public class when_reserving_a_proof_across_replicas(RedisReplayFixture redis) : given_a_redis_replay_store(redis)
{
    /// <summary>Only one competing reservation succeeds and replays do not extend its TTL.</summary>
    /// <returns>The scenario operation.</returns>
    [Fact]
    public async Task should_admit_exactly_one_contender_and_preserve_the_reservation_ttl()
    {
        await SeedCoverage(TimeSpan.FromSeconds(391));
        var replicas = new[] { Replica(), Replica() };
        var results = await Task.WhenAll(Enumerable.Range(0, 32).Select(index => Consume(replicas[index % 2])));
        results.Count(result => result == DpopReplayResult.Accepted).ShouldEqual(1);
        results.Count(result => result == DpopReplayResult.Replay).ShouldEqual(31);
        var ttl = await Database.KeyTimeToLiveAsync(ReplayKey("synthetic-proof"));
        ttl.ShouldNotBeNull();
        (ttl.GetValueOrDefault() > TimeSpan.Zero && ttl.GetValueOrDefault() <= TimeSpan.FromSeconds(390)).ShouldBeTrue();
        (await Consume(replicas[1])).ShouldEqual(DpopReplayResult.Replay);
        var remaining = await Database.KeyTimeToLiveAsync(ReplayKey("synthetic-proof"));
        (remaining <= ttl).ShouldBeTrue();
    }

    /// <summary>A new replica observes evidence left by a disposed replica.</summary>
    /// <returns>The scenario operation.</returns>
    [Fact]
    public async Task should_preserve_replay_evidence_when_a_replica_is_recreated()
    {
        await SeedCoverage(TimeSpan.FromSeconds(391));
        var original = Replica();
        (await Consume(original, "recreated-proof")).ShouldEqual(DpopReplayResult.Accepted);
        StopReplica(original);
        (await Consume(Replica(), "recreated-proof")).ShouldEqual(DpopReplayResult.Replay);
    }
}
