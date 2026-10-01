// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using Microsoft.Extensions.Caching.Distributed;

namespace Cratis.AuthProxy.AccessTokens.given;

/// <summary>
/// An in-memory <see cref="IDistributedCache"/> that also records every value written, so a spec can inspect what
/// would have reached a shared cache.
/// </summary>
public class RecordingDistributedCache : IDistributedCache
{
    readonly MemoryDistributedCache _inner = new(Options.Create(new MemoryDistributedCacheOptions()));

    /// <summary>
    /// Gets every value written, by key.
    /// </summary>
    public ConcurrentDictionary<string, byte[]> Written { get; } = new(StringComparer.Ordinal);

    /// <inheritdoc/>
    public byte[]? Get(string key) => _inner.Get(key);

    /// <inheritdoc/>
    public Task<byte[]?> GetAsync(string key, CancellationToken token = default) => _inner.GetAsync(key, token);

    /// <inheritdoc/>
    public void Refresh(string key) => _inner.Refresh(key);

    /// <inheritdoc/>
    public Task RefreshAsync(string key, CancellationToken token = default) => _inner.RefreshAsync(key, token);

    /// <inheritdoc/>
    public void Remove(string key) => _inner.Remove(key);

    /// <inheritdoc/>
    public Task RemoveAsync(string key, CancellationToken token = default) => _inner.RemoveAsync(key, token);

    /// <inheritdoc/>
    public void Set(string key, byte[] value, DistributedCacheEntryOptions options)
    {
        Written[key] = value;
        _inner.Set(key, value, options);
    }

    /// <inheritdoc/>
    public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
    {
        Written[key] = value;
        return _inner.SetAsync(key, value, options, token);
    }
}
