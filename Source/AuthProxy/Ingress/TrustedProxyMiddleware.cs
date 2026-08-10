// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Ingress;

/// <summary>
/// Records whether the connection came from a trusted proxy, before anything is allowed to rewrite the
/// request from its forwarded headers.
/// </summary>
/// <remarks>
/// Position is the whole point: this must sit immediately ahead of the forwarded-headers middleware, because
/// that middleware replaces <see cref="ConnectionInfo.RemoteIpAddress"/> with the address the header claimed.
/// Asking the question afterwards would compare the boundary against an attacker-chosen value and answer
/// yes for exactly the requests it exists to catch.
/// </remarks>
/// <param name="next">The next middleware in the pipeline.</param>
/// <param name="policy">The policy deciding which peers are trusted.</param>
public class TrustedProxyMiddleware(RequestDelegate next, ITrustedProxyPolicy policy)
{
    /// <inheritdoc cref="IMiddleware.InvokeAsync"/>
    public Task InvokeAsync(HttpContext context)
    {
        context.MarkTrustedProxyPeer(policy.IsTrusted(context.Connection.RemoteIpAddress));

        return next(context);
    }
}
