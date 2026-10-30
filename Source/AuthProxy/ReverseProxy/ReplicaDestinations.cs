// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Text;

namespace Cratis.AuthProxy.ReverseProxy;

/// <summary>
/// Names the destinations of a sticky service's replicas and recognizes them by the binding they carry.
/// </summary>
static class ReplicaDestinations
{
    /// <summary>
    /// Separates the binding from the replica part of a destination id.
    /// </summary>
    internal const char Separator = '#';

    /// <summary>
    /// Gets the id of a replica's destination. It is stable while the replica lives and does not contain its address.
    /// </summary>
    /// <param name="seedId">The id of the configured destination, which is also the access token binding.</param>
    /// <param name="replica">The replica.</param>
    /// <returns>The destination id.</returns>
    internal static string IdFor(string seedId, Uri replica)
    {
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(replica.Authority)));
        return $"{seedId}{Separator}{hash[..16]}";
    }

    /// <summary>
    /// Gets whether a destination id is the binding itself or a replica of it.
    /// </summary>
    /// <param name="destinationId">The destination id.</param>
    /// <param name="binding">The binding.</param>
    /// <returns>True when the destination carries the binding.</returns>
    internal static bool BelongsTo(string destinationId, string binding) =>
        string.Equals(destinationId, binding, StringComparison.Ordinal)
        || (destinationId.Length > binding.Length
            && destinationId.StartsWith(binding, StringComparison.Ordinal)
            && destinationId[binding.Length] == Separator);
}
