// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Arc.Identity;

namespace Cratis.AuthProxy.Identity;

/// <summary>
/// Defines the contract for resolving additional identity details from a microservice's
/// <c>/.cratis/me</c> endpoint and persisting them as the <c>.cratis-identity</c> cookie.
/// </summary>
public interface IIdentityDetailsResolver
{
    /// <summary>
    /// Calls <c>/.cratis/me</c> on every configured microservice that exposes an
    /// identity details endpoint, merges the results and writes (or refreshes) the
    /// <c>.cratis-identity</c> response cookie as a full <see cref="IdentityProviderResult"/>.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="principal">The <see cref="ClientPrincipal"/> representing the authenticated user.</param>
    /// <param name="tenantId">The resolved tenant identifier for this request.</param>
    /// <returns>
    /// A <see cref="Task{TResult}"/> resolving to the merged <see cref="IdentityProviderResult"/>,
    /// or an unauthorized result when any microservice reports HTTP 403.
    /// </returns>
    Task<IdentityProviderResult> Resolve(HttpContext context, ClientPrincipal principal, string tenantId);
}
