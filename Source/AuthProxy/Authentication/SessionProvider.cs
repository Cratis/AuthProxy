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
    /// The <see cref="AuthenticationProperties"/> item key holding the provider scheme AuthProxy recorded. It lives in
    /// the protected session cookie beside the claim and is only ever written by AuthProxy, so its presence proves
    /// the claim was recorded by AuthProxy and not carried over from a provider or from an earlier version.
    /// </summary>
    internal const string MarkerStateKey = "Cratis.AuthProxy.SessionProvider";

    /// <summary>
    /// Records the scheme on the principal and in the session properties, replacing any session claim the provider supplied.
    /// </summary>
    /// <param name="principal">The principal the session is created from.</param>
    /// <param name="properties">The session properties persisted in the cookie, when there are any.</param>
    /// <param name="scheme">The authentication scheme of the provider that completed the sign-in.</param>
    internal static void Stamp(ClaimsPrincipal principal, AuthenticationProperties? properties, string scheme)
    {
        if (properties is not null)
        {
            properties.Items[MarkerStateKey] = scheme;
        }

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
    /// <param name="properties">The session properties read from the cookie.</param>
    /// <param name="scheme">The recorded scheme when AuthProxy's marker and one matching well-formed claim exist; otherwise empty.</param>
    /// <returns><see langword="true"/> when the scheme is recorded; otherwise <see langword="false"/>.</returns>
    internal static bool TryRead(ClaimsPrincipal principal, AuthenticationProperties? properties, out string scheme)
    {
        var claims = principal.Claims.Where(_ => SessionClaims.IsReserved(_.Type)).ToArray();
        if (claims.Length == 1
            && IsWellFormed(claims[0])
            && properties is not null
            && properties.Items.TryGetValue(MarkerStateKey, out var marker)
            && string.Equals(marker, claims[0].Value, StringComparison.Ordinal))
        {
            scheme = claims[0].Value;
            return true;
        }

        scheme = string.Empty;
        return false;
    }

    static bool IsWellFormed(Claim claim) =>
        string.Equals(claim.Type, SessionClaims.ProviderScheme, StringComparison.Ordinal)
        && !string.IsNullOrWhiteSpace(claim.Value)
        && string.Equals(claim.Value, claim.Value.Trim(), StringComparison.Ordinal);

    /// <summary>
    /// Inspects whether the session records its provider.
    /// </summary>
    /// <param name="principal">The session principal.</param>
    /// <param name="properties">The session properties read from the cookie.</param>
    /// <returns>The state of the recorded provider.</returns>
    /// <remarks>
    /// A claim without AuthProxy's marker is never trusted: it may have been supplied by a provider before this was
    /// recorded, so the session counts as having no recorded provider, whatever claims it carries.
    /// </remarks>
    internal static SessionProviderState Inspect(ClaimsPrincipal principal, AuthenticationProperties? properties)
    {
        if (properties is null || !properties.Items.ContainsKey(MarkerStateKey))
        {
            return SessionProviderState.Missing;
        }

        return TryRead(principal, properties, out _) ? SessionProviderState.Recorded : SessionProviderState.Malformed;
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
        switch (Inspect(principal, context.Properties))
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
