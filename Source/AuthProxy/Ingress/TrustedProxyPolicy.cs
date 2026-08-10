// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Ingress;

/// <summary>
/// Decides which peers may speak for the client, from the deployment's declared
/// <see cref="C.Ingress"/> configuration.
/// </summary>
/// <remarks>
/// Bound through <see cref="IOptions{T}"/> rather than <see cref="IOptionsMonitor{T}"/> on purpose: the
/// forwarded-headers middleware reads its options once, when the pipeline is built, so a boundary that could
/// move underneath it at runtime would describe something the middleware is no longer doing.
/// <para>
/// Every entry is resolved once here. Startup validation has already refused a deployment naming an entry
/// that cannot be resolved, so an unresolvable entry can only be reached by constructing this directly, and
/// is dropped — never widened into trusting more than was asked for.
/// </para>
/// </remarks>
/// <param name="ingress">The ingress configuration declaring the boundary.</param>
public class TrustedProxyPolicy(IOptions<C.Ingress> ingress) : ITrustedProxyPolicy
{
    readonly C.Ingress _ingress = ingress.Value;
    readonly System.Net.IPNetwork[] _networks = [.. ingress.Value.TrustedProxies.Select(TrustedProxyAddress.Resolve).OfType<System.Net.IPNetwork>()];

    /// <inheritdoc/>
    public bool IsLegacyAllowAll =>
        _ingress.Mode == C.TrustedProxyMode.Configured && _ingress.TrustedProxies.Count == 0;

    /// <inheritdoc/>
    public void ApplyTo(ForwardedHeadersOptions options)
    {
        options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
        options.ForwardLimit = _ingress.ForwardLimit;

        // Loopback-only is the framework's own default, expressed by leaving the options as they came.
        if (_ingress.Mode == C.TrustedProxyMode.LoopbackOnly)
        {
            return;
        }

        options.KnownProxies.Clear();
        options.KnownIPNetworks.Clear();

        // The middleware runs a peer check only when at least one proxy or network is known, so leaving both
        // empty is what "believe every caller" means to it. That is the legacy posture, and it is also what
        // an explicit TrustAny asks for.
        if (_ingress.Mode == C.TrustedProxyMode.TrustAny || IsLegacyAllowAll)
        {
            return;
        }

        foreach (var network in _networks)
        {
            options.KnownIPNetworks.Add(network);
        }
    }

    /// <inheritdoc/>
    public bool IsTrusted(IPAddress? peer) => _ingress.Mode switch
    {
        C.TrustedProxyMode.TrustAny => true,
        C.TrustedProxyMode.LoopbackOnly => peer is not null && IPAddress.IsLoopback(peer),
        _ => IsLegacyAllowAll || (peer is not null && Matches(peer)),
    };

    /// <summary>
    /// Determines whether an address falls inside one of the declared networks.
    /// </summary>
    /// <param name="peer">The address to match.</param>
    /// <returns><see langword="true"/> when the address is inside a declared network; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// A dual-stack socket reports an IPv4 peer as its IPv6-mapped form, so an operator who declared
    /// <c>10.0.0.0/8</c> would otherwise see none of their own traffic match. The forwarded-headers
    /// middleware unmaps for exactly the same reason.
    /// </remarks>
    bool Matches(IPAddress peer) =>
        _networks.Any(network => network.Contains(peer))
        || (peer.IsIPv4MappedToIPv6 && _networks.Any(network => network.Contains(peer.MapToIPv4())));
}
