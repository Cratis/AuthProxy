// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Records, reads and validates the provider scheme a browser session was signed in with.
/// </summary>
internal static class SessionProvider
{
    /// <summary>
    /// Records the scheme on the principal, replacing any session claim the provider supplied.
    /// </summary>
    /// <param name="principal">The principal the session is created from.</param>
    /// <param name="scheme">The authentication scheme of the provider that completed the sign-in.</param>
    internal static void Stamp(ClaimsPrincipal principal, string scheme)
    {
        foreach (var identity in principal.Identities)
        {
            foreach (var claim in identity.Claims.Where(_ => SessionClaims.IsReserved(_.Type)).ToArray())
            {
                identity.TryRemoveClaim(claim);
            }
        }

        principal.Identities.First().AddClaim(new Claim(SessionClaims.ProviderScheme, scheme));
    }

    /// <summary>
    /// Reads the recorded provider scheme.
    /// </summary>
    /// <param name="principal">The session principal.</param>
    /// <param name="scheme">The recorded scheme when one well-formed claim exists; otherwise empty.</param>
    /// <returns><see langword="true"/> when the scheme is recorded; otherwise <see langword="false"/>.</returns>
    internal static bool TryRead(ClaimsPrincipal principal, out string scheme)
    {
        var claims = principal.Claims.Where(_ => SessionClaims.IsReserved(_.Type)).ToArray();
        if (claims.Length == 1
            && string.Equals(claims[0].Type, SessionClaims.ProviderScheme, StringComparison.Ordinal)
            && !string.IsNullOrWhiteSpace(claims[0].Value)
            && string.Equals(claims[0].Value, claims[0].Value.Trim(), StringComparison.Ordinal))
        {
            scheme = claims[0].Value;
            return true;
        }

        scheme = string.Empty;
        return false;
    }

    /// <summary>
    /// Inspects whether the session records its provider.
    /// </summary>
    /// <param name="principal">The session principal.</param>
    /// <returns>The state of the recorded provider.</returns>
    internal static SessionProviderState Inspect(ClaimsPrincipal principal)
    {
        if (TryRead(principal, out _))
        {
            return SessionProviderState.Recorded;
        }

        return principal.Claims.Any(_ => SessionClaims.IsReserved(_.Type))
            ? SessionProviderState.Malformed
            : SessionProviderState.Missing;
    }

    /// <summary>
    /// Ends a session that cannot be tied to one provider account.
    /// </summary>
    /// <param name="context">The cookie validation context.</param>
    /// <returns>A task that completes when the session has been rejected, if it must end.</returns>
    /// <remarks>
    /// Canonical sessions are governed by their own continuity checks. A session signed in by an earlier version
    /// records no provider; it continues while one provider is configured and ends when several are, because
    /// its subject alone no longer names one account.
    /// </remarks>
    internal static async Task Validate(CookieValidatePrincipalContext context)
    {
        var principal = context.Principal!;
        if (principal.Claims.Any(_ => CanonicalIdentityClaims.IsReserved(_.Type)))
        {
            return;
        }

        var reject = false;
        switch (Inspect(principal))
        {
            case SessionProviderState.Recorded:
                return;
            case SessionProviderState.Malformed:
                reject = true;
                break;
            default:
                try
                {
                    reject = context.HttpContext.RequestServices
                        .GetRequiredService<IOptionsMonitor<C.Authentication>>()
                        .CurrentValue.TotalProviderCount > 1;
                }
                catch (OptionsValidationException)
                {
                    reject = true;
                }

                break;
        }

        if (reject)
        {
            context.RejectPrincipal();
            await context.HttpContext.SignOutAsync(context.Scheme.Name);
        }
    }
}
