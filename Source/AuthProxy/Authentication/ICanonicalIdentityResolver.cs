// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Resolves and sanitizes canonical federated identity metadata from an authenticated principal.
/// </summary>
public interface ICanonicalIdentityResolver
{
    /// <summary>
    /// Resolves the identity for a fresh provider callback or validates an already enriched session principal.
    /// </summary>
    /// <param name="principal">The principal produced by the configured authentication handler.</param>
    /// <param name="authenticationScheme">The exact provider scheme, or the current session scheme.</param>
    /// <param name="validatedIssuer">
    /// The issuer obtained from the framework-validated OIDC security token. It must be supplied for a fresh
    /// canonical OIDC callback and must be absent for OAuth and already enriched session principals.
    /// </param>
    /// <param name="isFreshAuthentication">
    /// <see langword="true"/> only while handling the fresh provider callback. This permits the resolver to
    /// discard untrusted producer collisions before writing the first canonical claim set.
    /// </param>
    /// <returns>
    /// A legacy pass-through when the provider did not opt in, a sanitized canonical assertion on success,
    /// or one shared failed result for malformed, missing, duplicate, conflicting, or unsupported input.
    /// </returns>
    CanonicalIdentityResolution Resolve(
        ClaimsPrincipal? principal,
        string? authenticationScheme,
        string? validatedIssuer = null,
        bool isFreshAuthentication = false);
}
