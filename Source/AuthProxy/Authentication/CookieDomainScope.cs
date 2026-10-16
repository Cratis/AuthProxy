// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.ReverseProxy;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Evaluates a cookie domain and decides which hosts it covers.
/// </summary>
/// <remarks>
/// A domain cookie is sent to every host under the domain, so the domain has to name a real registrable scope:
/// not an address, not a top-level domain, not something a browser would refuse. Hosts are compared in the same
/// normalized form <see cref="ServiceRoutes"/> uses, so a Unicode host and its punycode spelling are one host.
/// </remarks>
public static class CookieDomainScope
{
    /// <summary>
    /// Evaluates a configured cookie domain.
    /// </summary>
    /// <param name="domain">The configured domain, with or without a leading dot.</param>
    /// <param name="normalized">The normalized domain without a leading dot when it is usable.</param>
    /// <returns>The reason the domain is unusable, or <see cref="CookieDomainRejection.None"/>.</returns>
    public static CookieDomainRejection Evaluate(string? domain, out string normalized)
    {
        normalized = string.Empty;
        var trimmed = (domain ?? string.Empty).Trim().TrimStart('.');

        if (!trimmed.All(char.IsAscii))
        {
            return CookieDomainRejection.NotAscii;
        }

        if (trimmed.Contains(':') && IPAddress.TryParse(trimmed.Trim('[', ']'), out _))
        {
            return CookieDomainRejection.IpAddress;
        }

        if (!ServiceRoutes.TryParseHost(trimmed, out var host))
        {
            return CookieDomainRejection.NotAHost;
        }

        if (host.Port is not null)
        {
            return CookieDomainRejection.HasPort;
        }

        if (IPAddress.TryParse(host.Host, out _))
        {
            return CookieDomainRejection.IpAddress;
        }

        if (!host.Host.Contains('.') || host.Host.EndsWith('.'))
        {
            return CookieDomainRejection.SingleLabel;
        }

        normalized = host.Host;
        return CookieDomainRejection.None;
    }

    /// <summary>
    /// Gets whether a host is the domain or a subdomain of it.
    /// </summary>
    /// <param name="normalizedDomain">The domain, as returned by <see cref="Evaluate"/>.</param>
    /// <param name="host">The host to test, without a port.</param>
    /// <returns><see langword="true"/> when the cookie would be sent to the host; otherwise <see langword="false"/>.</returns>
    public static bool Covers(string normalizedDomain, string host) =>
        string.Equals(host, normalizedDomain, StringComparison.OrdinalIgnoreCase)
        || host.EndsWith($".{normalizedDomain}", StringComparison.OrdinalIgnoreCase);
}
