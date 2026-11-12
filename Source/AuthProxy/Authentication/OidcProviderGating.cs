// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Applies the opt-in gating settings of an OIDC provider: static authorization parameters and the verified e-mail requirement.
/// </summary>
internal static class OidcProviderGating
{
    /// <summary>
    /// Adds the configured static authorization parameters to an outgoing authorization request.
    /// </summary>
    /// <param name="message">The protocol message that becomes the authorization request.</param>
    /// <param name="provider">The provider the request is for.</param>
    internal static void ApplyAuthorizationParameters(OpenIdConnectMessage message, C.OidcProvider provider)
    {
        foreach (var parameter in provider.AuthorizationParameters)
        {
            message.SetParameter(parameter.Key, parameter.Value);
        }
    }

    /// <summary>
    /// Makes the e-mail and its verification flag from the user-info response reach the principal under the claim types the gate reads.
    /// </summary>
    /// <param name="options">The OIDC handler options.</param>
    /// <param name="provider">The provider being configured.</param>
    internal static void MapVerifiedEmailClaims(OpenIdConnectOptions options, C.OidcProvider provider)
    {
        if (!provider.RequireVerifiedEmail)
        {
            return;
        }

        options.ClaimActions.MapUniqueJsonKey(EmailVerifiedClaimType(provider), VerifiedEmailGate.DefaultEmailVerifiedClaimType);
        options.ClaimActions.MapUniqueJsonKey(EmailClaimType(provider), VerifiedEmailGate.DefaultEmailClaimType);
    }

    /// <summary>
    /// Creates the admission check for a provider that requires a verified e-mail address.
    /// </summary>
    /// <param name="provider">The provider to check callbacks for.</param>
    /// <returns>The check, or <see langword="null"/> when the provider does not require one.</returns>
    internal static Func<ClaimsPrincipal?, bool>? CreateAdmission(C.OidcProvider provider) =>
        provider.RequireVerifiedEmail
            ? principal => VerifiedEmailGate.IsSatisfied(
                principal,
                EmailClaimType(provider),
                EmailVerifiedClaimType(provider),
                provider.CanonicalIdentity is null)
            : null;

    static string EmailClaimType(C.OidcProvider provider) =>
        provider.CanonicalIdentity?.EmailClaimType is { Length: > 0 } claim ? claim : VerifiedEmailGate.DefaultEmailClaimType;

    static string EmailVerifiedClaimType(C.OidcProvider provider) =>
        provider.CanonicalIdentity?.EmailVerifiedClaimType is { Length: > 0 } claim ? claim : VerifiedEmailGate.DefaultEmailVerifiedClaimType;
}
