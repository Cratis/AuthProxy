// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using StackExchange.Redis;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.BearerRoutes.Dpop;

/// <summary>Uses atomic Redis time, coverage and SET NX checks without a local replay cache.</summary>
/// <param name="options">The deployment's dedicated Redis settings.</param>
/// <param name="clock">The local clock compared with Redis on every operation.</param>
/// <param name="database">An optional database supplied by deterministic specifications.</param>
/// <param name="healthLockTimeout">An optional health-lock timeout supplied by deterministic specifications.</param>
internal sealed class RedisDpopReplayStore(IOptions<C.AuthProxy> options, TimeProvider clock, IDatabase? database = null, TimeSpan? healthLockTimeout = null) : IDpopReplayStore, IDisposable
{
    /// <summary>The atomic Redis time, coverage, quarantine and SET NX operation; every key shares a cluster slot.</summary>
    internal const string Script =
        "local t = redis.call('TIME')\n" +
        "local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)\n" +
        "if math.abs(now - tonumber(ARGV[1])) > 30000 then return {3, now} end\n" +
        "if redis.call('EXISTS', KEYS[1]) == 0 then\n" +
        "redis.call('SET', KEYS[1], now, 'NX')\n" +
        "end\n" +
        "local coverage = tonumber(redis.call('GET', KEYS[1]))\n" +
        "if not coverage or now - coverage < 390000 then return {3, now} end\n" +
        "if ARGV[2] == '0' then return {1, now} end\n" +
        "if redis.call('SET', KEYS[2], '1', 'NX', 'PX', 390000) then return {1, now} end\n" +
        "return {2, now}";

    static readonly TimeSpan _healthInterval = TimeSpan.FromSeconds(10);
    readonly SemaphoreSlim _connect = new(1, 1);
    readonly SemaphoreSlim _healthLock = new(1, 1);
    readonly TimeSpan _healthLockTimeout = healthLockTimeout ?? TimeSpan.FromSeconds(5);
    long? _healthCheckedAt;
    DpopReplayResult _healthResult = DpopReplayResult.Unavailable;
    ConnectionMultiplexer? _connection;

    /// <inheritdoc/>
    public async Task<DpopReplayResult> CheckHealth(CancellationToken cancellationToken)
    {
        if (!await _healthLock.WaitAsync(_healthLockTimeout, cancellationToken)) return DpopReplayResult.Unavailable;
        try
        {
            if (_healthCheckedAt is { } checkedAt && clock.GetElapsedTime(checkedAt, clock.GetTimestamp()) < _healthInterval) return _healthResult;
            var startedAt = clock.GetTimestamp();
            _healthResult = await Execute(null, cancellationToken);
            _healthCheckedAt = startedAt;
            return _healthResult;
        }
        finally
        {
            _healthLock.Release();
        }
    }

    /// <inheritdoc/>
    public Task<DpopReplayResult> TryConsume(string origin, string jkt, string jti, CancellationToken cancellationToken) => Execute(DpopEncoding.Hash("resource\0" + origin + "\0" + jkt + "\0" + jti), cancellationToken);

    /// <inheritdoc/>
    public void Dispose()
    {
        _connection?.Dispose();
        _connect.Dispose();
        _healthLock.Dispose();
    }

    async Task<ConnectionMultiplexer> Connection(CancellationToken cancellationToken)
    {
        await _connect.WaitAsync(cancellationToken);
        try
        {
            if (_connection is not null) return _connection;
            var settings = ConfigurationOptions.Parse(options.Value.Dpop.ReplayStore.Redis.ConnectionString);
            settings.AbortOnConnectFail = false;
            settings.ConnectTimeout = 2000;
            settings.AsyncTimeout = 2000;
            _connection = await ConnectionMultiplexer.ConnectAsync(settings);
            return _connection;
        }
        finally
        {
            _connect.Release();
        }
    }

    async Task<DpopReplayResult> Execute(string? key, CancellationToken cancellationToken)
    {
        try
        {
            var settings = options.Value.Dpop.ReplayStore.Redis;
            if (string.IsNullOrWhiteSpace(settings.ConnectionString) || string.IsNullOrWhiteSpace(settings.KeyPrefix)) return DpopReplayResult.Unavailable;
            var replayDatabase = database ?? (await Connection(cancellationToken)).GetDatabase();
            if (database is null && _connection?.IsConnected != true) return DpopReplayResult.Unavailable;
            var prefix = "{" + settings.KeyPrefix + "}:";
            var startedAt = clock.GetTimestamp();
            var local = clock.GetUtcNow().ToUnixTimeMilliseconds();
            var operation = replayDatabase.ScriptEvaluateAsync(
                Script,
                [prefix + "coverage", prefix + (key ?? "health")],
                [local, key is null ? "0" : "1"]);
            var result = (RedisResult[]?)await operation.WaitAsync(cancellationToken);
            return ReadResult(result, local, startedAt);
        }
        catch (Exception exception) when (exception is RedisException or TimeoutException or ArgumentException or InvalidOperationException or OperationCanceledException or InvalidCastException or FormatException or OverflowException)
        {
            return DpopReplayResult.Unavailable;
        }
    }

    DpopReplayResult ReadResult(RedisResult[]? result, long local, long startedAt)
    {
        if (result is not { Length: 2 }) return DpopReplayResult.Unavailable;
        if (result.Any(field => field.IsNull)) return DpopReplayResult.Unavailable;
        if (clock.GetElapsedTime(startedAt, clock.GetTimestamp()) >= _healthInterval) return DpopReplayResult.Unavailable;
        if (!ClockIsCurrent((long)result[1], local)) return DpopReplayResult.Unavailable;
        return (int)result[0] switch
        {
            1 => DpopReplayResult.Accepted,
            2 => DpopReplayResult.Replay,
            _ => DpopReplayResult.Unavailable,
        };
    }

    bool ClockIsCurrent(decimal serverTime, long startedAt)
    {
        var completedAt = clock.GetUtcNow().ToUnixTimeMilliseconds();
        return Math.Abs(serverTime - startedAt) <= 30000 && Math.Abs(serverTime - completedAt) <= 30000;
    }
}
