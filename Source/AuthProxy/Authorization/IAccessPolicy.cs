// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authorization;

/// <summary>
/// Defines the policy deciding whether an authenticated caller may pass the proxy at all.
/// </summary>
public interface IAccessPolicy
{
    /// <summary>
    /// Determines whether the configuration declares anything to authorize against.
    /// </summary>
    /// <param name="config">The auth proxy configuration to read.</param>
    /// <returns><see langword="true"/> when at least one requirement is declared; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// Nothing declared is the state every deployment that never opts in is in, and it has to stay
    /// indistinguishable from this feature not existing. Asking first keeps the whole evaluation — and the
    /// question of which service a request targets — off the path of a deployment that does not use it.
    /// </remarks>
    bool IsConfigured(C.AuthProxy config);

    /// <summary>
    /// Evaluates the configured claim requirements against the caller on the current request.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>, carrying the authenticated principal.</param>
    /// <param name="config">The auth proxy configuration to read.</param>
    /// <returns>The <see cref="AccessDecision"/> for this caller and request.</returns>
    AccessDecision Evaluate(HttpContext context, C.AuthProxy config);

    /// <summary>
    /// Evaluates the claim requirements of a bearer route against the principal of the token presented on it.
    /// </summary>
    /// <param name="user">The token's principal, after the route's claim mappings.</param>
    /// <param name="config">The auth proxy configuration to read.</param>
    /// <param name="serviceName">The name of the service the route belongs to.</param>
    /// <param name="route">The bearer route the token was presented on.</param>
    /// <returns>The <see cref="AccessDecision"/> for this principal on this route.</returns>
    /// <remarks>
    /// A bearer route belongs to exactly one service, whatever the request names, so its target is not worked out
    /// from the request. The root requirements and the service's apply as they do to a browser session, unless the
    /// route sets <see cref="C.BearerRoute.IgnoreDeploymentRequiredClaims"/>; the route's own
    /// <see cref="C.BearerRoute.RequiredClaims"/> always apply on top.
    /// </remarks>
    AccessDecision Evaluate(ClaimsPrincipal user, C.AuthProxy config, string serviceName, C.BearerRoute route);
}
