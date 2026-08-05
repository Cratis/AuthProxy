// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity;

/// <summary>
/// Defines the contract for remembering, across requests, that a principal was authorized in a tenant.
/// </summary>
/// <remarks>
/// Resolving identity details means calling <c>/.cratis/me</c> on every configured service, and the answer
/// includes whether the caller is authorized at all. Doing that on every request would put a fan-out of
/// backend calls in front of every proxied request, so the outcome is remembered on the client — which
/// makes the remembered value an authorization decision travelling through the caller's own browser, and
/// therefore something the caller must not be able to write.
/// </remarks>
public interface IIdentityAuthorizationCache
{
    /// <summary>
    /// Records that the given principal was authorized in the given tenant.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>, whose response the record is written to.</param>
    /// <param name="principal">The authorized principal.</param>
    /// <param name="tenantId">The tenant the principal was authorized in.</param>
    void Record(HttpContext context, ClientPrincipal principal, string tenantId);

    /// <summary>
    /// Determines whether the current request carries proof that this principal was already authorized in
    /// this tenant.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="principal">The principal to check.</param>
    /// <param name="tenantId">The tenant to check.</param>
    /// <returns><see langword="true"/> when a valid, unexpired record for this principal and tenant is present; otherwise <see langword="false"/>.</returns>
    bool IsAuthorized(HttpContext context, ClientPrincipal principal, string tenantId);

    /// <summary>
    /// Clears any recorded authorization from the response.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    void Clear(HttpContext context);
}
