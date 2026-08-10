// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Represents how AuthProxy decides which callers may speak for the client through forwarded headers.
/// </summary>
/// <remarks>
/// Everything a forwarded header claims — the client's address and the scheme the browser used — is
/// attacker-controlled unless the caller that sent it is one the deployment put there. The mode states which
/// callers those are, so the answer is a deployment decision rather than an accident of defaults.
/// </remarks>
public enum TrustedProxyMode
{
    /// <summary>
    /// Trust only the addresses and ranges named in <see cref="Ingress.TrustedProxies"/>.
    /// </summary>
    /// <remarks>
    /// The default. Naming nothing is the legacy allow-all posture kept for compatibility: every caller is
    /// believed, and a warning at startup names the configuration key that leaves it.
    /// </remarks>
    Configured = 0,

    /// <summary>
    /// Trust only a caller on the loopback interface, which is the ASP.NET Core framework default.
    /// </summary>
    /// <remarks>
    /// Correct for a sidecar or a local development host. A deployment behind an ingress controller, a load
    /// balancer, or a CDN never sees the loopback address as the peer, so this refuses every forwarded
    /// header it receives.
    /// </remarks>
    LoopbackOnly = 1,

    /// <summary>
    /// Trust every caller.
    /// </summary>
    /// <remarks>
    /// Only correct when nothing but the deployment's own ingress can open a connection to AuthProxy. State
    /// it explicitly rather than relying on an empty <see cref="Ingress.TrustedProxies"/>, so the choice is
    /// visible in the deployment rather than inferred from an omission.
    /// </remarks>
    TrustAny = 2,
}
