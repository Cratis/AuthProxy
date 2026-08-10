// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.ComponentModel.DataAnnotations;

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents the ingress configuration — where AuthProxy sits on the network, and therefore which callers
/// it believes when they speak for someone else.
/// </summary>
/// <remarks>
/// A reverse proxy only knows the client's real address and the scheme the browser used because whatever sits
/// in front of it says so, in <c>X-Forwarded-For</c> and <c>X-Forwarded-Proto</c>. Those headers are ordinary
/// request headers, so any caller that can open a connection can send them. The boundary is therefore not a
/// detail of the header format but a statement about the network: which peers are the deployment's own
/// infrastructure, and how many of them a request legitimately passes through.
/// </remarks>
public class Ingress
{
    /// <summary>
    /// The configuration section key for the ingress settings.
    /// </summary>
    public const string SectionKey = $"{AuthProxy.SectionKey}:Ingress";

    /// <summary>
    /// Gets or sets how the set of trusted peers is decided. Defaults to
    /// <see cref="TrustedProxyMode.Configured"/>.
    /// </summary>
    public TrustedProxyMode Mode { get; set; } = TrustedProxyMode.Configured;

    /// <summary>
    /// Gets or sets the peers whose forwarded headers are believed, as IP addresses
    /// (<c>10.0.0.7</c>, <c>2001:db8::1</c>) or CIDR ranges (<c>10.0.0.0/8</c>, <c>2001:db8::/32</c>).
    /// </summary>
    /// <remarks>
    /// These are the addresses AuthProxy sees as the immediate peer — the ingress controller, load balancer,
    /// service mesh sidecar, or CDN egress range in front of it — not the addresses of clients. An entry that
    /// cannot be parsed fails startup naming the offending value rather than being quietly dropped, because a
    /// trusted proxy that is silently not trusted is a boundary that is silently in the wrong place.
    /// </remarks>
    public IList<string> TrustedProxies { get; set; } = [];

    /// <summary>
    /// Gets or sets how many forwarded entries are consumed from the right of <c>X-Forwarded-For</c>,
    /// which is how many trusted proxies a request legitimately passes through. Defaults to <c>1</c>.
    /// </summary>
    /// <remarks>
    /// Set it to the number of hops the deployment actually has — an ingress controller alone is <c>1</c>, a
    /// CDN in front of a load balancer is <c>2</c>. Every hop counted must itself be a trusted peer, so
    /// raising this without listing the intermediate addresses in <see cref="TrustedProxies"/> changes
    /// nothing. It directly decides which address is reported as the client: with too few hops the reported
    /// address is the deployment's own inner proxy, and with more hops than exist the reported address is
    /// whatever the outermost caller chose to write.
    /// </remarks>
    [Range(1, 16)]
    public int ForwardLimit { get; set; } = 1;
}
