// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using Microsoft.Extensions.Caching.Distributed;

namespace Cratis.AuthProxy.AccessTokens.given;

/// <summary>
/// An in-memory cache whose absolute and sliding expiration follow the spec's clock, recording every write.
/// </summary>
/// <param name="timeProvider">The clock shared with the token store.</param>
public class RecordingDistributedCache(TimeProvider timeProvider) : IDistributedCache
{
    readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets every value written, by key.
    /// </summary>
    public ConcurrentDictionary<string, byte[]> Written { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets or sets a write barrier for concurrency specs.
    /// </summary>
    public Func<string, Task>? BeforeSet { get; set; }

    /// <inheritdoc/>
    public byte[]? Get(string key) => ReadEntry(key);

    /// <inheritdoc/>
    public Task<byte[]?> GetAsync(string key, CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();
        return Task.FromResult(ReadEntry(key));
    }

    /// <inheritdoc/>
    public void Refresh(string key) => ReadEntry(key);

    /// <inheritdoc/>
    public Task RefreshAsync(string key, CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();
        ReadEntry(key);
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public void Remove(string key) => _entries.TryRemove(key, out _);

    /// <inheritdoc/>
    public Task RemoveAsync(string key, CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();
        _entries.TryRemove(key, out _);
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public void Set(string key, byte[] value, DistributedCacheEntryOptions options) => WriteEntry(key, value, options);

    /// <inheritdoc/>
    public async Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();
        if (BeforeSet is { } beforeSet)
        {
            await beforeSet(key);
        }

        WriteEntry(key, value, options);
    }

    byte[]? ReadEntry(string key)
    {
        if (!_entries.TryGetValue(key, out var entry))
        {
            return null;
        }

        var now = timeProvider.GetUtcNow();
        if ((entry.AbsoluteExpiration is { } absolute && now >= absolute)
            || (entry.SlidingExpiration is { } sliding && now >= entry.LastAccess + sliding))
        {
            _entries.TryRemove(key, out _);
            return null;
        }

        _entries[key] = entry with { LastAccess = now };
        return entry.Value;
    }

    void WriteEntry(string key, byte[] value, DistributedCacheEntryOptions options)
    {
        var now = timeProvider.GetUtcNow();
        var absolute = options.AbsoluteExpirationRelativeToNow is { } relative ? now + relative : options.AbsoluteExpiration;
        Written[key] = value;
        _entries[key] = new(value, absolute, options.SlidingExpiration, now);
    }

    sealed record Entry(byte[] Value, DateTimeOffset? AbsoluteExpiration, TimeSpan? SlidingExpiration, DateTimeOffset LastAccess);
}
