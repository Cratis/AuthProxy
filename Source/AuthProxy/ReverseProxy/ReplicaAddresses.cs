// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Net.Sockets;

namespace Cratis.AuthProxy.ReverseProxy;

/// <summary>
/// Turns the addresses a DNS lookup answered with into replica URIs, dropping those that can never be a replica.
/// </summary>
static class ReplicaAddresses
{
    /// <summary>
    /// The most replicas that are kept.
    /// </summary>
    internal const int MaximumReplicas = 64;

    /// <summary>
    /// Builds the replica URIs for a set of addresses.
    /// </summary>
    /// <param name="baseUrl">The configured base URL; only its host is replaced.</param>
    /// <param name="addresses">The addresses DNS answered with.</param>
    /// <returns>The distinct, deterministically ordered replica URIs, at most <see cref="MaximumReplicas"/>.</returns>
    internal static IReadOnlyList<Uri> From(Uri baseUrl, IEnumerable<IPAddress> addresses) =>
        [.. addresses
            .Select(address => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address)
            .Where(IsReplicaCandidate)
            .DistinctBy(address => address.ToString())
            .OrderBy(address => address.AddressFamily)
            .ThenBy(address => Convert.ToHexString(address.GetAddressBytes()), StringComparer.Ordinal)
            .Take(MaximumReplicas)
            .Select(address => new UriBuilder(baseUrl) { Host = address.ToString() }.Uri)];

    static bool IsReplicaCandidate(IPAddress address)
    {
        if (IPAddress.IsLoopback(address)
            || address.Equals(IPAddress.Any)
            || address.Equals(IPAddress.IPv6Any)
            || address.Equals(IPAddress.None)
            || address.Equals(IPAddress.IPv6None))
        {
            return false;
        }

        return address.AddressFamily switch
        {
            AddressFamily.InterNetwork => IsPublicOrPrivateIPv4(address.GetAddressBytes()),
            AddressFamily.InterNetworkV6 => !address.IsIPv6LinkLocal && !address.IsIPv6Multicast,
            _ => false,
        };
    }

    static bool IsPublicOrPrivateIPv4(byte[] bytes) =>
        bytes[0] != 0 // 0.0.0.0/8
        && !(bytes[0] == 169 && bytes[1] == 254) // link-local, including cloud metadata
        && bytes[0] < 224; // multicast, reserved and broadcast
}
