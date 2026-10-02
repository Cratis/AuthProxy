// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes;

/// <summary>
/// Defines the forwarding of a bearer-route request to the backend of the service declaring the route.
/// </summary>
public interface IBearerRouteForwarder
{
    /// <summary>
    /// Forwards the request to the route's service backend.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="route">The route the request is on.</param>
    /// <param name="identity">
    /// What AuthProxy vouches for, or <see langword="null"/> to forward without any identity — the
    /// protected-resource metadata request.
    /// </param>
    /// <returns>A <see cref="Task"/> that completes when the response has been relayed.</returns>
    Task Forward(HttpContext context, ResolvedBearerRoute route, BearerForwardedIdentity? identity);
}
