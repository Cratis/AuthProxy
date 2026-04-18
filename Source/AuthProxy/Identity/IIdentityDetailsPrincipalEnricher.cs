// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity;

/// <summary>
/// Enriches the principal payload used when calling the identity details provider.
/// </summary>
public interface IIdentityDetailsPrincipalEnricher
{
    /// <summary>
    /// Enriches the current <paramref name="principal"/> for the active request context.
    /// </summary>
    /// <param name="context">The current HTTP context.</param>
    /// <param name="principal">The principal to enrich.</param>
    /// <returns>An enriched principal payload.</returns>
    ClientPrincipal Enrich(HttpContext context, ClientPrincipal principal);
}
