// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace Cratis.AuthProxy.BearerRoutes.Introspection;

/// <summary>
/// Remembers, briefly, which tokens an introspection endpoint answered were active.
/// </summary>
/// <param name="timeProvider">The clock.</param>
/// <remarks>
/// Only active answers are stored, and only under a hash of the endpoint, client and token, never the token
/// itself. An entry is never used past its expiry, and when the cache is full a new answer is not stored
/// rather than an existing one evicted or the cache grown.
/// </remarks>
public sealed class IntrospectionCache(TimeProvider timeProvider)
{
    readonly ConcurrentDictionary<string, DateTimeOffset> _entries = new(StringComparer.Ordinal);
    readonly Lock _storeLock = new();

    /// <summary>
    /// Gets the keys currently held. The keys are hashes.
    /// </summary>
    internal IReadOnlyCollection<string> Keys => [.. _entries.Keys];

    /// <summary>
    /// Creates the cache key for a token presented to an endpoint by a client.
    /// </summary>
    /// <param name="endpoint">The introspection endpoint.</param>
    /// <param name="clientId">The client the endpoint is asked as.</param>
    /// <param name="token">The token.</param>
    /// <returns>A hex SHA-256 hash; it does not contain the token.</returns>
    public static string CreateKey(string endpoint, string clientId, string token) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"{endpoint}\0{clientId}\0{token}")));

    /// <summary>
    /// Determines whether a fresh active answer is held for a key.
    /// </summary>
    /// <param name="key">The key from <see cref="CreateKey"/>.</param>
    /// <returns><see langword="true"/> when a non-expired entry exists; otherwise <see langword="false"/>.</returns>
    public bool IsActive(string key)
    {
        if (!_entries.TryGetValue(key, out var expiresAt))
        {
            return false;
        }

        if (expiresAt > timeProvider.GetUtcNow())
        {
            return true;
        }

        _entries.TryRemove(new KeyValuePair<string, DateTimeOffset>(key, expiresAt));
        return false;
    }

    /// <summary>
    /// Stores an active answer.
    /// </summary>
    /// <param name="key">The key from <see cref="CreateKey"/>.</param>
    /// <param name="lifetime">How long the answer may be reused.</param>
    /// <param name="maximum">The most entries the cache may hold.</param>
    /// <returns><see langword="true"/> when stored; <see langword="false"/> when the lifetime is not positive or the cache is full.</returns>
    public bool Store(string key, TimeSpan lifetime, int maximum)
    {
        if (lifetime <= TimeSpan.Zero)
        {
            return false;
        }

        lock (_storeLock)
        {
            var now = timeProvider.GetUtcNow();
            if (!_entries.ContainsKey(key) && _entries.Count >= maximum)
            {
                foreach (var entry in _entries.Where(_ => _.Value <= now))
                {
                    _entries.TryRemove(entry);
                }

                if (_entries.Count >= maximum)
                {
                    return false;
                }
            }

            _entries[key] = now + lifetime;
            return true;
        }
    }
}
