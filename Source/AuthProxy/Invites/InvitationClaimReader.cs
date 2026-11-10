// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Cratis.AuthProxy.Authentication;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Reads the claims an invitation completion depends on, from either the invitation token or the authenticated
/// principal, refusing duplicates, padding and oversized values.
/// </summary>
static class InvitationClaimReader
{
    const int MaximumClaimValueLength = 2048;

    /// <summary>
    /// Reads a claim that must occur exactly once in a token, refusing duplicates, padding and oversized values.
    /// </summary>
    /// <param name="token">The raw JWT string.</param>
    /// <param name="claimType">The claim type to look up.</param>
    /// <param name="value">The single exact claim value when accepted.</param>
    /// <returns><see langword="true"/> when the claim occurs exactly once with an acceptable value; otherwise <see langword="false"/>.</returns>
    internal static bool TryGetSingleTokenClaim(string token, ClaimType claimType, out string value)
    {
        try
        {
            return TryGetSingleExactClaim(new JsonWebTokenHandler().ReadJsonWebToken(token).Claims, claimType, out value);
        }
        catch (ArgumentException)
        {
            value = string.Empty;
            return false;
        }
    }

    /// <summary>
    /// Reads a claim that must occur exactly once on a principal, refusing duplicates, padding and oversized values.
    /// </summary>
    /// <param name="principal">The authenticated principal.</param>
    /// <param name="claimType">The claim type to look up.</param>
    /// <param name="value">The single exact claim value when accepted.</param>
    /// <returns><see langword="true"/> when the claim occurs exactly once with an acceptable value; otherwise <see langword="false"/>.</returns>
    internal static bool TryGetSingleExactClaim(ClaimsPrincipal principal, ClaimType claimType, out string value) =>
        TryGetSingleExactClaim(principal.Claims, claimType, out value);

    /// <summary>
    /// Compares two strings without leaking, through timing, where they first differ.
    /// </summary>
    /// <param name="expected">The expected value.</param>
    /// <param name="actual">The presented value.</param>
    /// <returns><see langword="true"/> when both values are identical; otherwise <see langword="false"/>.</returns>
    internal static bool FixedTimeEquals(string expected, string actual) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(actual));

    /// <summary>
    /// Resolves the authenticating account's email and its provider-supplied verification status.
    /// </summary>
    /// <param name="principal">The authenticated principal completing the invitation.</param>
    /// <returns>The authenticated email, with an empty address when none is available.</returns>
    /// <remarks>
    /// <c language="text">preferred_username</c> is a username, not an address — for a GitHub OAuth provider it is conventionally
    /// mapped from <c language="text">login</c>. It is read only when it actually holds an address, which several OIDC providers
    /// put there (Entra's is the user principal name). Returning a login name here would make a provider that
    /// supplied no address at all indistinguishable from one that supplied somebody else's.
    /// </remarks>
    internal static AuthenticatedEmail ResolveAuthenticatedEmail(ClaimsPrincipal principal)
    {
        var address = FirstClaimValue(principal, "email", ClaimTypes.Email)
            ?? PreferredUsernameWhenAddress(principal)
            ?? string.Empty;
        return new AuthenticatedEmail(address, ReadEmailVerified(principal));
    }

    /// <summary>
    /// Resolves the subject an invitation is exchanged for.
    /// </summary>
    /// <param name="principal">The authenticated principal.</param>
    /// <param name="identity">The canonical identity, when one resolved.</param>
    /// <returns>The subject, or an empty string when none is available.</returns>
    internal static string ResolveSubject(ClaimsPrincipal principal, CanonicalFederatedIdentity? identity) =>
        identity?.Subject
        ?? FirstClaimValue(principal, "sub", "oid", ClaimTypes.NameIdentifier, "id")
        ?? string.Empty;

    /// <summary>
    /// Resolves the identity provider an invitation is exchanged for.
    /// </summary>
    /// <param name="principal">The authenticated principal.</param>
    /// <param name="identity">The canonical identity, when one resolved.</param>
    /// <returns>The identity provider, or an empty string when none is available.</returns>
    internal static string ResolveIdentityProvider(ClaimsPrincipal principal, CanonicalFederatedIdentity? identity) =>
        identity?.ProviderKey
        ?? FirstClaimValue(principal, "iss", "identity_provider", "http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/identityprovider")
        ?? principal.Identity?.AuthenticationType
        ?? string.Empty;

    static bool TryGetSingleExactClaim(IEnumerable<Claim> claims, ClaimType claimType, out string value)
    {
        var matches = claims.Where(_ => string.Equals(_.Type, claimType.Value, StringComparison.Ordinal)).ToArray();
        var accepted = matches.Length == 1 && IsExactClaimValue(matches[0].Value);
        value = accepted ? matches[0].Value : string.Empty;
        return accepted;
    }

    static string? FirstClaimValue(ClaimsPrincipal principal, params ClaimType[] claimTypes) =>
        claimTypes.Select(_ => principal.FindFirst(_.Value)).FirstOrDefault(_ => _ is not null)?.Value;

    static bool? ReadEmailVerified(ClaimsPrincipal principal) =>
        bool.TryParse(principal.FindFirst("email_verified")?.Value, out var verified) ? verified : null;

    static string? PreferredUsernameWhenAddress(ClaimsPrincipal principal)
    {
        var preferredUsername = principal.FindFirst("preferred_username")?.Value;
        return InviteMiddleware.IsAnEmailAddress(preferredUsername) ? preferredUsername : null;
    }

    static bool IsExactClaimValue(string value) =>
        !string.IsNullOrWhiteSpace(value)
        && value.Length <= MaximumClaimValueLength
        && string.Equals(value, value.Trim(), StringComparison.Ordinal);
}
