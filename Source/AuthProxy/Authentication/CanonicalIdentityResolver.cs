// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Resolves the configured canonical federated identity contract for an authenticated principal and replaces
/// producer-supplied collisions with the canonical claims authored by AuthProxy.
/// </summary>
/// <param name="configuration">The independently validated authentication configuration monitor.</param>
/// <remarks>
/// Resolution establishes provider authentication metadata only. It does not grant application membership,
/// roles, scopes, authorization, or ownership of the subject value.
/// </remarks>
public sealed class CanonicalIdentityResolver(IOptionsMonitor<C.Authentication> configuration) : ICanonicalIdentityResolver
{
    /// <summary>
    /// Resolves the canonical identity for a fresh provider callback or validates an already enriched session principal.
    /// </summary>
    /// <param name="principal">The principal produced by the configured authentication handler.</param>
    /// <param name="authenticationScheme">The exact provider scheme, or the current session scheme.</param>
    /// <param name="validatedIssuer">
    /// The issuer obtained from the framework-validated OIDC security token. It must be supplied for a fresh canonical
    /// OIDC callback and must be absent for OAuth and already enriched session principals.
    /// </param>
    /// <param name="isFreshAuthentication">
    /// <see langword="true"/> only while handling the fresh provider callback, allowing producer collisions to be
    /// discarded before AuthProxy writes the canonical claim set; otherwise, <see langword="false"/>.
    /// </param>
    /// <returns>
    /// A legacy pass-through when the provider did not opt in, a sanitized canonical assertion on success, or a
    /// fail-closed result for malformed, missing, duplicate, conflicting, or unsupported input.
    /// </returns>
    public CanonicalIdentityResolution Resolve(
        ClaimsPrincipal? principal,
        string? authenticationScheme,
        string? validatedIssuer = null,
        bool isFreshAuthentication = false)
    {
        C.Authentication current;
        try
        {
            current = configuration.CurrentValue;
        }
        catch (OptionsValidationException)
        {
            return CanonicalIdentityResolution.Failed();
        }

        var provider = FindProvider(current, authenticationScheme);
        if (provider is null)
        {
            if (isFreshAuthentication)
            {
                return CanonicalIdentityResolution.SanitizedLegacy(principal);
            }

            if (!HasReservedClaims(principal))
            {
                return CanonicalIdentityResolution.Legacy(principal);
            }

            return string.Equals(authenticationScheme, CookieAuthenticationDefaults.AuthenticationScheme, StringComparison.Ordinal)
                ? ValidateEnrichedPrincipal(current, principal)
                : CanonicalIdentityResolution.Failed();
        }

        if (provider.Value.Identity is null)
        {
            if (isFreshAuthentication)
            {
                return CanonicalIdentityResolution.SanitizedLegacy(principal);
            }

            return HasReservedClaims(principal)
                ? CanonicalIdentityResolution.Failed()
                : CanonicalIdentityResolution.Legacy(principal);
        }

        if (principal is null)
        {
            return CanonicalIdentityResolution.Failed();
        }

        if (!isFreshAuthentication && validatedIssuer is null && HasReservedClaims(principal))
        {
            return ValidateEnrichedPrincipal(current, principal);
        }

        var identityConfiguration = provider.Value.Identity;
        if (!TryGetSingleExactClaim(principal, identityConfiguration.SubjectClaimType, out var subject))
        {
            return CanonicalIdentityResolution.Failed();
        }

        string issuer;
        if (provider.Value.IsOidc)
        {
            if (validatedIssuer is null
                || !CanonicalIssuer.TryNormalize(validatedIssuer, out issuer))
            {
                return CanonicalIdentityResolution.Failed();
            }
        }
        else if (!CanonicalIssuer.TryNormalize(identityConfiguration.Issuer, out issuer))
        {
            return CanonicalIdentityResolution.Failed();
        }

        var canonical = new CanonicalFederatedIdentity(identityConfiguration.ProviderKey, issuer, subject);
        return CanonicalIdentityResolution.Success(canonical, ReplaceReservedClaims(principal, canonical));
    }

    static bool TryGetSingleExactClaim(ClaimsPrincipal principal, string claimType, out string value)
    {
        var claims = principal.Claims
            .Where(_ => string.Equals(_.Type, claimType, StringComparison.OrdinalIgnoreCase))
            .ToArray();

        if (claims.Length != 1
            || !string.Equals(claims[0].Type, claimType, StringComparison.Ordinal)
            || string.IsNullOrWhiteSpace(claims[0].Value)
            || !string.Equals(claims[0].Value, claims[0].Value.Trim(), StringComparison.Ordinal)
            || claims[0].Value.Length > 2048)
        {
            value = string.Empty;
            return false;
        }

        value = claims[0].Value;
        return true;
    }

    static bool HasReservedClaims(ClaimsPrincipal? principal) =>
        principal?.Claims.Any(claim => CanonicalIdentityClaims.IsReserved(claim.Type)) == true;

    static ClaimsPrincipal ReplaceReservedClaims(ClaimsPrincipal principal, CanonicalFederatedIdentity canonical)
    {
        var identities = CanonicalIdentityResolution.SanitizedLegacy(principal).Principal!.Identities.ToList();

        if (identities.Count == 0)
        {
            identities.Add(new ClaimsIdentity());
        }

        identities[0].AddClaim(new Claim(CanonicalIdentityClaims.ProviderKey, canonical.ProviderKey));
        identities[0].AddClaim(new Claim(CanonicalIdentityClaims.Issuer, canonical.NormalizedIssuer));
        identities[0].AddClaim(new Claim(CanonicalIdentityClaims.Subject, canonical.Subject));
        return new ClaimsPrincipal(identities);
    }

    static Provider? FindProvider(C.Authentication current, string? authenticationScheme)
    {
        if (string.IsNullOrWhiteSpace(authenticationScheme))
        {
            return null;
        }

        var matches = current.OidcProviders
            .Where(_ => string.Equals(OidcProviderScheme.FromName(_.Name), authenticationScheme, StringComparison.Ordinal))
            .Select(_ => new Provider(_.CanonicalIdentity, true))
            .Concat(current.OAuthProviders
                .Where(_ => string.Equals(OidcProviderScheme.FromName(_.Name), authenticationScheme, StringComparison.Ordinal))
                .Select(_ => new Provider(_.CanonicalIdentity, false)))
            .ToArray();

        return matches.Length == 1 ? matches[0] : null;
    }

    static CanonicalIdentityResolution ValidateEnrichedPrincipal(C.Authentication current, ClaimsPrincipal? principal)
    {
        var reservedClaims = principal?.Claims.Where(_ => CanonicalIdentityClaims.IsReserved(_.Type)).ToArray() ?? [];
        if (principal is null
            || reservedClaims.Length != CanonicalIdentityClaims.All.Length
            || !TryGetSingleExactClaim(principal, CanonicalIdentityClaims.ProviderKey, out var providerKey)
            || !TryGetSingleExactClaim(principal, CanonicalIdentityClaims.Issuer, out var issuer)
            || !TryGetSingleExactClaim(principal, CanonicalIdentityClaims.Subject, out var subject)
            || !CanonicalIssuer.TryNormalize(issuer, out var normalizedIssuer)
            || !string.Equals(issuer, normalizedIssuer, StringComparison.Ordinal))
        {
            return CanonicalIdentityResolution.Failed();
        }

        var configuredOidc = current.OidcProviders
            .Where(_ => string.Equals(_.CanonicalIdentity?.ProviderKey, providerKey, StringComparison.Ordinal))
            .ToArray();
        var configuredOAuth = current.OAuthProviders
            .Where(_ => string.Equals(_.CanonicalIdentity?.ProviderKey, providerKey, StringComparison.Ordinal))
            .ToArray();

        if (configuredOidc.Length + configuredOAuth.Length != 1)
        {
            return CanonicalIdentityResolution.Failed();
        }

        if (configuredOAuth.Length == 1
            && (!CanonicalIssuer.TryNormalize(configuredOAuth[0].CanonicalIdentity!.Issuer, out var expectedIssuer)
                || !string.Equals(expectedIssuer, normalizedIssuer, StringComparison.Ordinal)))
        {
            return CanonicalIdentityResolution.Failed();
        }

        return CanonicalIdentityResolution.Success(new(providerKey, normalizedIssuer, subject), principal);
    }

    readonly record struct Provider(C.CanonicalIdentity? Identity, bool IsOidc);
}
