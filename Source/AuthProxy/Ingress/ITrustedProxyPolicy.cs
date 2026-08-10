// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Ingress;

/// <summary>
/// Defines the boundary between callers whose forwarded headers AuthProxy believes and callers whose
/// forwarded headers are just request headers an attacker chose.
/// </summary>
public interface ITrustedProxyPolicy
{
    /// <summary>
    /// Gets a value indicating whether the deployment has fallen back to believing every caller because it
    /// named no trusted proxies.
    /// </summary>
    bool IsLegacyAllowAll { get; }

    /// <summary>
    /// Applies the boundary to the forwarded-headers middleware's options.
    /// </summary>
    /// <param name="options">The <see cref="ForwardedHeadersOptions"/> to configure.</param>
    /// <remarks>
    /// The same policy configures the middleware and answers <see cref="IsTrusted"/>, so what the middleware
    /// consumes and what the rest of the proxy considers trustworthy are one decision rather than two that
    /// can drift apart.
    /// </remarks>
    void ApplyTo(ForwardedHeadersOptions options);

    /// <summary>
    /// Determines whether a peer may speak for the client.
    /// </summary>
    /// <param name="peer">The address the connection actually came from, before any header was applied.</param>
    /// <returns><see langword="true"/> when the peer is trusted; otherwise <see langword="false"/>.</returns>
    bool IsTrusted(IPAddress? peer);
}
