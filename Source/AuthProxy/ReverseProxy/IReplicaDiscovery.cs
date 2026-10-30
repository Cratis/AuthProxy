// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy;

/// <summary>
/// Discovers the individually reachable replicas of a service's backend.
/// </summary>
/// <remarks>
/// Public only so that the security specs can substitute it; it is not meant as an extension point.
/// </remarks>
public interface IReplicaDiscovery
{
    /// <summary>
    /// Discovers the replicas of a backend.
    /// </summary>
    /// <param name="baseUrl">The configured base URL of the backend. Scheme, port and path of every replica come from it.</param>
    /// <param name="replicaHost">The DNS host name that resolves to the replicas.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> for the lookup.</param>
    /// <returns>The absolute URIs of the replicas. An empty list means none were found.</returns>
    Task<IReadOnlyList<Uri>> Discover(Uri baseUrl, string replicaHost, CancellationToken cancellationToken);
}
