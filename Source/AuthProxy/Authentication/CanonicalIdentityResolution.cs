// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Represents the outcome of resolving AuthProxy's canonical federated identity contract for an authenticated principal.
/// </summary>
/// <remarks>
/// A configured provider fails closed: unsuccessful resolution exposes neither an identity nor a principal. An
/// unconfigured provider remains in legacy pass-through mode and returns a principal without reserved canonical
/// claims. A successful canonical identity is authentication metadata only and does not grant application access.
/// </remarks>
public sealed class CanonicalIdentityResolution
{
    CanonicalIdentityResolution(bool isConfigured, bool succeeded, CanonicalFederatedIdentity? identity, ClaimsPrincipal? principal)
    {
        IsConfigured = isConfigured;
        Succeeded = succeeded;
        Identity = identity;
        Principal = principal;
    }

    /// <summary>
    /// Gets a value indicating whether the selected authentication provider opted into canonical identity resolution.
    /// </summary>
    /// <remarks>
    /// When <see langword="false"/>, the result is a legacy pass-through and contains no canonical identity assertion.
    /// </remarks>
    public bool IsConfigured { get; }

    /// <summary>
    /// Gets a value indicating whether resolution completed without malformed, missing, duplicate, or conflicting input.
    /// </summary>
    /// <remarks>
    /// Legacy pass-through results also succeed. Inspect <see cref="IsConfigured"/> to distinguish them from a resolved
    /// canonical identity.
    /// </remarks>
    public bool Succeeded { get; }

    /// <summary>
    /// Gets the provider-aware identity after successful canonical resolution, or <see langword="null"/> for legacy
    /// pass-through and failed results.
    /// </summary>
    /// <remarks>
    /// The value identifies the authenticated provider account. It does not establish membership, roles, scopes,
    /// authorization, or ownership of the subject value.
    /// </remarks>
    public CanonicalFederatedIdentity? Identity { get; }

    /// <summary>
    /// Gets the principal containing one AuthProxy-authored canonical claim set after successful canonical resolution,
    /// a reserved-claim-sanitized principal in fresh legacy pass-through mode, the already sanitized principal in
    /// subsequent legacy resolution, or <see langword="null"/> when configured resolution fails.
    /// </summary>
    public ClaimsPrincipal? Principal { get; }

    /// <summary>
    /// Creates a successful legacy pass-through result for a provider without canonical identity configuration.
    /// </summary>
    /// <param name="principal">The authenticated principal after reserved claims have been removed, if one was supplied.</param>
    /// <returns>A successful, unconfigured result containing <paramref name="principal"/> and no canonical identity.</returns>
    internal static CanonicalIdentityResolution Legacy(ClaimsPrincipal? principal) => new(false, true, null, principal);

    /// <summary>
    /// Creates a successful legacy pass-through result after removing every claim in the reserved canonical namespace.
    /// </summary>
    /// <param name="principal">The authenticated legacy principal, if one was supplied.</param>
    /// <returns>A successful, unconfigured result containing a sanitized clone of <paramref name="principal"/>.</returns>
    internal static CanonicalIdentityResolution SanitizedLegacy(ClaimsPrincipal? principal)
    {
        if (principal is null)
        {
            return Legacy(null);
        }

        var identities = principal.Identities.Select(identity =>
        {
            var clone = new ClaimsIdentity(identity);
            foreach (var claim in clone.Claims.Where(_ => CanonicalIdentityClaims.IsReserved(_.Type)).ToArray())
            {
                clone.RemoveClaim(claim);
            }

            return clone;
        });

        return Legacy(new ClaimsPrincipal(identities));
    }

    /// <summary>
    /// Creates a fail-closed result for a provider whose canonical identity could not be resolved unambiguously.
    /// </summary>
    /// <returns>An unsuccessful, configured result that exposes neither an identity nor a principal.</returns>
    internal static CanonicalIdentityResolution Failed() => new(true, false, null, null);

    /// <summary>
    /// Creates a successful canonical identity result.
    /// </summary>
    /// <param name="identity">The resolved provider-aware identity metadata.</param>
    /// <param name="principal">The authenticated principal containing the AuthProxy-authored canonical claim set.</param>
    /// <returns>A successful, configured result containing <paramref name="identity"/> and <paramref name="principal"/>.</returns>
    internal static CanonicalIdentityResolution Success(CanonicalFederatedIdentity identity, ClaimsPrincipal principal) => new(true, true, identity, principal);
}
