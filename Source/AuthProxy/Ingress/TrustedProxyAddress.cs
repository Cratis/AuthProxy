// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Net.Sockets;

namespace Cratis.AuthProxy.Ingress;

/// <summary>
/// Resolves a configured trusted-proxy entry to the network of addresses it names.
/// </summary>
/// <remarks>
/// One place decides what an entry means, so the configuration validator that refuses a bad one at startup
/// and the policy that matches a peer at request time can never disagree about it.
/// </remarks>
public static class TrustedProxyAddress
{
    const int IPv4BitLength = 32;
    const int IPv6BitLength = 128;

    /// <summary>
    /// Resolves an entry written as an IP address or a CIDR range.
    /// </summary>
    /// <param name="value">The configured entry.</param>
    /// <returns>The network the entry names, or <see langword="null"/> when it names none.</returns>
    /// <remarks>
    /// A bare address resolves to the single-address network containing only it, so an entry is always a
    /// range and matching is one operation rather than two. A CIDR range is normalized to its network
    /// address, so <c>10.0.0.1/8</c> and <c>10.0.0.0/8</c> name the same range — the conventional reading,
    /// and the one every other tool an operator copies a range from applies.
    /// </remarks>
    public static IPNetwork? Resolve(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var entry = value.Trim();

        if (entry.Contains('/', StringComparison.Ordinal))
        {
            return IPNetwork.TryParse(entry, out var network) ? network : null;
        }

        if (!IPAddress.TryParse(entry, out var address))
        {
            return null;
        }

        return new IPNetwork(address, address.AddressFamily == AddressFamily.InterNetworkV6 ? IPv6BitLength : IPv4BitLength);
    }
}
