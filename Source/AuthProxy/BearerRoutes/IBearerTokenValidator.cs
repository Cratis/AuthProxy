// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BearerRoutes;

/// <summary>
/// Defines the validation of the access token presented on a bearer route.
/// </summary>
public interface IBearerTokenValidator
{
    /// <summary>
    /// Validates the access token the request carries against the route it targets.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <param name="route">The bearer route the request targets.</param>
    /// <param name="cancellationToken">The request's cancellation token.</param>
    /// <returns>The validation outcome.</returns>
    Task<BearerTokenValidation> Validate(HttpRequest request, ResolvedBearerRoute route, CancellationToken cancellationToken);
}
