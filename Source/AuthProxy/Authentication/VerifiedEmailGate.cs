// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Decides whether a principal presents exactly one e-mail address that its provider reports as verified.
/// </summary>
internal static class VerifiedEmailGate
{
    /// <summary>The claim type an OIDC provider uses for the e-mail address when none is configured.</summary>
    internal const string DefaultEmailClaimType = "email";

    /// <summary>The claim type an OIDC provider uses for the verification flag when none is configured.</summary>
    internal const string DefaultEmailVerifiedClaimType = "email_verified";

    /// <summary>
    /// Determines whether the principal has exactly one distinct e-mail address and a single, true verification claim.
    /// </summary>
    /// <param name="principal">The principal the provider callback produced.</param>
    /// <param name="emailClaimType">The claim type that carries the e-mail address.</param>
    /// <param name="emailVerifiedClaimType">The claim type that carries the verification flag.</param>
    /// <param name="includeMappedEmail">Whether the inbound-mapped e-mail claim type counts as the same address.</param>
    /// <returns><see langword="true"/> when the requirement is met; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// Anything but exactly one claim whose value is <see langword="true"/> (case-insensitive, no surrounding whitespace) fails,
    /// so a missing, conflicting or ambiguous answer never admits anybody.
    /// </remarks>
    internal static bool IsSatisfied(ClaimsPrincipal? principal, string emailClaimType, string emailVerifiedClaimType, bool includeMappedEmail)
    {
        if (principal is null)
        {
            return false;
        }

        var claims = principal.Claims.ToArray();
        var addresses = claims
            .Where(_ => _.Type == emailClaimType || (includeMappedEmail && _.Type == ClaimTypes.Email))
            .Select(_ => _.Value.Trim())
            .Where(_ => _.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count();

        var verified = claims.Where(_ => _.Type == emailVerifiedClaimType).ToArray();
        return addresses == 1
            && verified.Length == 1
            && string.Equals(verified[0].Value, bool.TrueString, StringComparison.OrdinalIgnoreCase);
    }
}
