// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Net.Sockets;

namespace Cratis.AuthProxy.Ingress;

/// <summary>
/// Tells public addresses from loopback, private, link-local and shared ones.
/// </summary>
internal static class PublicAddress
{
    /// <summary>
    /// Gets whether an address is reachable from the public internet.
    /// </summary>
    /// <param name="address">The address to test; <see langword="null"/> is not public.</param>
    /// <returns><see langword="true"/> for a public address; otherwise <see langword="false"/>.</returns>
    internal static bool Is(IPAddress? address)
    {
        if (address is null)
        {
            return false;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (IPAddress.IsLoopback(address))
        {
            return false;
        }

        var bytes = address.GetAddressBytes();
        return address.AddressFamily switch
        {
            AddressFamily.InterNetwork => !IsPrivateV4(bytes),
            AddressFamily.InterNetworkV6 => !(address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || (bytes[0] & 0xFE) == 0xFC),
            _ => false
        };
    }

    static bool IsPrivateV4(byte[] bytes) =>
        bytes[0] == 0
        || bytes[0] == 10
        || (bytes[0] == 100 && (bytes[1] & 0xC0) == 64)
        || (bytes[0] == 169 && bytes[1] == 254)
        || (bytes[0] == 172 && (bytes[1] & 0xF0) == 16)
        || (bytes[0] == 192 && bytes[1] == 168);
}
