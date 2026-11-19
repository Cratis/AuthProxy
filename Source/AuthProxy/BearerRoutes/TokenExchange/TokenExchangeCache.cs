// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Microsoft.IdentityModel.JsonWebTokens;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.BearerRoutes.TokenExchange;

/// <summary>Bounds successful results and in-flight work; concurrent callers share one Identity request.</summary>
/// <param name="timeProvider">The clock.</param>
public sealed class TokenExchangeCache(TimeProvider timeProvider)
{
    readonly Lock _gate = new();
    readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    readonly Dictionary<string, Task<TokenExchangeResult>> _flights = new(StringComparer.Ordinal);

    /// <summary>Hashes the credential and every trusted configuration dimension; never log the key.</summary>
    /// <param name="configuration">The trusted configuration.</param>
    /// <param name="issuer">The external issuer.</param>
    /// <param name="tenant">The exact requested tenant.</param>
    /// <param name="token">The raw credential.</param>
    /// <returns>A SHA-256 key that retains no raw credential.</returns>
    public static string CreateKey(C.BearerTokenExchange configuration, string issuer, string tenant, string token) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new { configuration, issuer, tenant, token })));

    /// <summary>Reuses a fresh result or shares one exchange, without caching any failure.</summary>
    /// <param name="key">The opaque key.</param>
    /// <param name="maximum">The storage and in-flight bound.</param>
    /// <param name="exchange">The authority call.</param>
    /// <param name="cancellationToken">The caller's cancellation.</param>
    /// <returns>The authority outcome, still requiring normal JWT validation.</returns>
    public Task<TokenExchangeResult> GetOrExchange(string key, int maximum, Func<Task<TokenExchangeResult>> exchange, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        TaskCompletionSource<TokenExchangeResult> completion;
        lock (_gate)
        {
            if (_entries.TryGetValue(key, out var entry) && entry.ExpiresAt > timeProvider.GetUtcNow()) return Task.FromResult(entry.Result);
            _entries.Remove(key);
            if (_flights.TryGetValue(key, out var flight)) return flight.WaitAsync(cancellationToken);
            if (_flights.Count >= maximum) return Task.FromResult(new TokenExchangeResult(TokenExchangeVerdict.Unavailable));
            completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
            _flights.Add(key, completion.Task);
        }
        _ = Complete(key, maximum, exchange, completion);
        return completion.Task.WaitAsync(cancellationToken);
    }

    /// <summary>Discards a result that failed JWT validation or authorization.</summary>
    /// <param name="key">The opaque key.</param>
    public void Evict(string key)
    {
        lock (_gate) _entries.Remove(key);
    }

    static DateTimeOffset? Deadline(TokenExchangeResult result, DateTimeOffset now)
    {
        if (result.Verdict != TokenExchangeVerdict.Success || result.ExpiresIn is < 1 or > 300) return null;
        try
        {
            var jwt = new JsonWebToken(result.Token);
            if (!jwt.TryGetPayloadValue<long>("exp", out var expiration)) return null;
            var expiresAt = DateTimeOffset.FromUnixTimeSeconds(expiration);
            var deadline = now.AddSeconds(result.ExpiresIn);
            if (expiresAt < deadline) deadline = expiresAt;
            return deadline > now ? deadline : null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    async Task Complete(string key, int maximum, Func<Task<TokenExchangeResult>> exchange, TaskCompletionSource<TokenExchangeResult> completion)
    {
        try
        {
            var result = await exchange();
            lock (_gate)
            {
                Store(key, maximum, result);
                _flights.Remove(key);
            }
            completion.TrySetResult(result);
        }
        catch (Exception)
        {
            // Neither exception objects nor their text (which may contain credentials) escape the shared operation.
            lock (_gate) _flights.Remove(key);
            completion.TrySetResult(new(TokenExchangeVerdict.Unavailable));
        }
    }

    void Store(string key, int maximum, TokenExchangeResult result)
    {
        var now = timeProvider.GetUtcNow();
        if (Deadline(result, now) is not { } deadline) return;
        foreach (var expired in _entries.Where(_ => _.Value.ExpiresAt <= now).Select(_ => _.Key).ToArray()) _entries.Remove(expired);
        while (_entries.Count >= maximum) _entries.Remove(_entries.MinBy(_ => _.Value.ExpiresAt).Key);
        _entries[key] = new(deadline, result);
    }

    sealed record Entry(DateTimeOffset ExpiresAt, TokenExchangeResult Result)
    {
        public override string ToString() => nameof(Entry);
    }
}
