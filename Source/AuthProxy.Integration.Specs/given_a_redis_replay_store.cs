// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.BearerRoutes.Dpop;
using Microsoft.Extensions.Options;
using StackExchange.Redis;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Integration.Specs;

/// <summary>Isolates each replay scenario behind a unique Redis key prefix.</summary>
/// <param name="redis">The shared Redis process.</param>
public class given_a_redis_replay_store(RedisReplayFixture redis) : Specification
{
    const string Origin = "https://api.example.test";
    const string Thumbprint = "synthetic-thumbprint";
    readonly List<RedisDpopReplayStore> _stores = [];
    readonly string _prefix = "dpop-spec-" + Guid.NewGuid().ToString("N");

    /// <summary>Gets the Redis process lifecycle.</summary>
    protected RedisReplayFixture Redis => redis;

    /// <summary>Gets the database for evidence inspection and coverage setup.</summary>
    protected IDatabase Database => redis.Database;

    /// <summary>Gets this scenario's coverage marker.</summary>
    protected RedisKey CoverageKey => "{" + _prefix + "}:coverage";

    /// <summary>Creates an independent production replay-store replica.</summary>
    /// <param name="clock">The replica clock, or the system clock.</param>
    /// <returns>The replay store.</returns>
    protected IDpopReplayStore Replica(TimeProvider? clock = null)
    {
        var options = new C.AuthProxy();
        options.Dpop.ReplayStore.Redis = new() { ConnectionString = redis.Endpoint, KeyPrefix = _prefix };
        var store = new RedisDpopReplayStore(Options.Create(options), clock ?? TimeProvider.System);
        _stores.Add(store);
        return store;
    }

    /// <summary>Disposes a replica without changing Redis evidence.</summary>
    /// <param name="store">The replica to close.</param>
    protected void StopReplica(IDpopReplayStore store)
    {
        var instance = (RedisDpopReplayStore)store;
        _stores.Remove(instance);
        instance.Dispose();
    }

    /// <summary>Sets coverage age relative to Redis TIME, without waiting a retention window.</summary>
    /// <param name="age">The age of the coverage marker.</param>
    /// <returns>The marker write operation.</returns>
    protected async Task SeedCoverage(TimeSpan age)
    {
        var milliseconds = (long)await Database.ScriptEvaluateAsync("local t = redis.call('TIME'); return t[1] * 1000 + math.floor(t[2] / 1000)");
        await Database.StringSetAsync(CoverageKey, milliseconds - (long)age.TotalMilliseconds);
    }

    /// <summary>Gets the production-format key for a synthetic proof identifier.</summary>
    /// <param name="jti">The synthetic proof identifier.</param>
    /// <returns>The replay key.</returns>
    protected RedisKey ReplayKey(string jti) => "{" + _prefix + "}:" + DpopEncoding.Hash("resource\0" + Origin + "\0" + Thumbprint + "\0" + jti);

    /// <summary>Reserves a synthetic proof through the production Lua path.</summary>
    /// <param name="store">The independent replica.</param>
    /// <param name="jti">The synthetic proof identifier.</param>
    /// <returns>The reservation result.</returns>
    protected Task<DpopReplayResult> Consume(IDpopReplayStore store, string jti = "synthetic-proof") => store.TryConsume(Origin, Thumbprint, jti, CancellationToken.None);

    /// <summary>Closes all scenario-owned replica connections.</summary>
    protected void Destroy()
    {
        foreach (var store in _stores) store.Dispose();
    }
}
