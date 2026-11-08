// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.SignIns;

/// <summary>
/// The fixed set of upstream claims AuthProxy has itself verified during an OpenID Connect sign-in, held for the
/// one request that completes it.
/// </summary>
/// <remarks>
/// The claims are read only from the identity token the OpenID Connect handler has just validated (signature,
/// issuer, audience, lifetime, state and PKCE) — never from the user-info response, the session principal, a
/// request header or a body field. They live in <see cref="HttpContext.Items"/>, which only server code can
/// write, so nothing a caller sends can reach them. A claim that is absent, repeated, empty or oversized is
/// omitted — never defaulted — so a receiver can tell "not verified" from a value.
/// </remarks>
sealed class VerifiedUpstreamClaims
{
    /// <summary>The names, on the wire and in the token, of the claims that may be forwarded.</summary>
    internal static readonly string[] Names = ["iss", "sub", "idp", "idp_sub", "github_id", "auth_time", "jti"];

    const string ItemKey = "Cratis.AuthProxy.VerifiedUpstreamClaims";
    const int MaximumLength = 2048;

    VerifiedUpstreamClaims(string scheme, IReadOnlyDictionary<string, object> values)
    {
        Scheme = scheme;
        Values = values;
    }

    /// <summary>Gets the authentication scheme whose validated token the claims came from.</summary>
    internal string Scheme { get; }

    /// <summary>Gets the verified claim values by name; <c language="text">auth_time</c> is a number, every other value a string.</summary>
    internal IReadOnlyDictionary<string, object> Values { get; }

    /// <summary>
    /// Records the verifiable claims of a token the OpenID Connect handler has just validated.
    /// </summary>
    /// <param name="context">The request completing the sign-in.</param>
    /// <param name="scheme">The authentication scheme that validated the token.</param>
    /// <param name="validatedToken">The validated identity token.</param>
    internal static void Capture(HttpContext context, string scheme, SecurityToken? validatedToken)
    {
        context.Items.Remove(ItemKey);
        if (validatedToken is not JsonWebToken jwt)
        {
            return;
        }

        var values = new Dictionary<string, object>(StringComparer.Ordinal);
        foreach (var name in Names)
        {
            if (TryRead(jwt.Claims, name, out var value))
            {
                values[name] = value;
            }
        }

        context.Items[ItemKey] = new VerifiedUpstreamClaims(scheme, values);
    }

    /// <summary>
    /// Gets the claims verified for this request, provided they came from the given scheme.
    /// </summary>
    /// <param name="context">The request completing the sign-in.</param>
    /// <param name="scheme">The scheme the sign-in completed on.</param>
    /// <returns>The verified claims, or <see langword="null"/> when none were verified for that scheme.</returns>
    internal static VerifiedUpstreamClaims? For(HttpContext context, string? scheme) =>
        scheme is not null
        && context.Items.TryGetValue(ItemKey, out var held)
        && held is VerifiedUpstreamClaims claims
        && claims.Values.Count > 0
        && string.Equals(claims.Scheme, scheme, StringComparison.Ordinal)
            ? claims
            : null;

    static bool TryRead(IEnumerable<Claim> claims, string name, out object value)
    {
        value = string.Empty;
        var matches = claims.Where(_ => string.Equals(_.Type, name, StringComparison.Ordinal)).Take(2).ToArray();
        if (matches.Length != 1)
        {
            return false;
        }

        var text = matches[0].Value.Trim();
        if (text.Length == 0 || text.Length > MaximumLength)
        {
            return false;
        }

        if (name == "auth_time")
        {
            if (!long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds))
            {
                return false;
            }

            value = seconds;
            return true;
        }

        value = text;
        return true;
    }
}
