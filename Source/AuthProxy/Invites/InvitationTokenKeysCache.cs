// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Holds one configured invitation issuer's synchronized retrieval deadlines and last good keys.
/// </summary>
internal sealed class InvitationTokenKeysCache : IDisposable
{
    KeySnapshot? _snapshot;

    /// <summary>Gets the gate serializing retrievals and deadline access.</summary>
    internal SemaphoreSlim Gate { get; } = new(1, 1);

    /// <summary>Gets or sets the automatic refresh deadline.</summary>
    internal DateTimeOffset RefreshAfter { get; set; }

    /// <summary>Gets or sets the failed-fetch backoff deadline.</summary>
    internal DateTimeOffset RetryAfter { get; set; }

    /// <summary>Gets or sets the next allowed requested refresh.</summary>
    internal DateTimeOffset RequestedRefreshAfter { get; set; }

    /// <summary>Gets or sets the most recently scheduled background refresh.</summary>
    internal Task? BackgroundRefresh { get; set; }

    /// <summary>Gets or sets the last successful key snapshot.</summary>
    internal KeySnapshot? Snapshot
    {
        get => Volatile.Read(ref _snapshot);
        set => Volatile.Write(ref _snapshot, value);
    }

    /// <inheritdoc/>
    public void Dispose() => Gate.Dispose();

    /// <summary>
    /// Keeps a key set and its successful fetch time together for lock-free readers.
    /// </summary>
    /// <param name="Keys">The trusted public keys.</param>
    /// <param name="FetchedAt">The successful retrieval time.</param>
    internal sealed record KeySnapshot(IReadOnlyDictionary<string, SecurityKey> Keys, DateTimeOffset FetchedAt);
}
