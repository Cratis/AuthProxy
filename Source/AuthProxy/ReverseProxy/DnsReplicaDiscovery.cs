// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.ReverseProxy;

/// <summary>
/// Discovers replicas with A and AAAA lookups only, so DNS can never supply a port or a scheme.
/// </summary>
sealed class DnsReplicaDiscovery : IReplicaDiscovery
{
    /// <inheritdoc/>
    public async Task<IReadOnlyList<Uri>> Discover(Uri baseUrl, string replicaHost, CancellationToken cancellationToken) =>
        ReplicaAddresses.From(baseUrl, await Dns.GetHostAddressesAsync(replicaHost, cancellationToken));
}
