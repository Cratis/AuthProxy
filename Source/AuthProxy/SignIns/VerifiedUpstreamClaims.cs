// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.SignIns;

/// <summary>
/// The fixed set of upstream claims AuthProxy has itself verified during an OpenID Connect sign-in, held for the
/// one request that completes it.
/// </summary>
/// <remarks>
/// Each claim has exactly one source, a token AuthProxy fully validated in this very authorization-code exchange —
/// never the user-info response, the session principal, a request header or a body field. The identity token
/// (validated by the OpenID Connect handler: signature, issuer, audience, lifetime, state and PKCE) supplies
/// <c language="text">iss</c>, <c language="text">sub</c>, <c language="text">auth_time</c> and <c language="text">jti</c>;
/// the access token (validated by <see cref="UpstreamAccessTokenValidator"/>) supplies <c language="text">idp</c>,
/// <c language="text">idp_sub</c> and <c language="text">github_id</c>. A claim is never taken from the other token, so
/// one injected into the identity token is ignored. Without a valid access token whose <c language="text">sub</c>
/// equals the identity token's, no claim is sent at all. They live in <see cref="HttpContext.Items"/>, which only server code can
/// write, so nothing a caller sends can reach them. A claim that is absent, repeated, empty or oversized is
/// omitted — never defaulted — so a receiver can tell "not verified" from a value.
/// </remarks>
sealed class VerifiedUpstreamClaims
{
    /// <summary>The names, on the wire and in the token, of the claims that may be forwarded.</summary>
    internal static readonly string[] Names = ["iss", "sub", "idp", "idp_sub", "github_id", "auth_time", "jti"];

    const string ItemKey = "Cratis.AuthProxy.VerifiedUpstreamClaims";
    const int MaximumLength = 2048;

    /// <summary>The claims read from the identity token; every other one in <see cref="Names"/> comes from the access token.</summary>
    static readonly string[] _identityTokenClaims = ["iss", "sub", "auth_time", "jti"];

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
    /// Validates the access token returned in the same code exchange as the identity token the handler just validated,
    /// then records the verifiable claims of both. Nothing is recorded unless the access token passes every check.
    /// </summary>
    /// <param name="context">The handler's validated-token context; its token endpoint response holds the access token.</param>
    /// <param name="scheme">The authentication scheme that validated the identity token.</param>
    /// <returns>A task that completes once the claims are recorded or discarded.</returns>
    internal static async Task Capture(Microsoft.AspNetCore.Authentication.OpenIdConnect.TokenValidatedContext context, string scheme)
    {
        var services = context.HttpContext.RequestServices;
        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger("Cratis.AuthProxy.SignIns.VerifiedUpstreamClaims");
        var idToken = AsJsonWebToken(context.SecurityToken);
        JsonWebToken? accessToken = null;
        if (idToken is not null
            && services.GetRequiredService<IOptionsMonitor<C.AuthProxy>>().CurrentValue.SignIn?.IncludeVerifiedUpstreamClaims == true)
        {
            var options = context.Options;
            accessToken = await UpstreamAccessTokenValidator.Validate(
                context.TokenEndpointResponse?.AccessToken,
                idToken,
                [options.ClientId!, options.Resource!],
                options.TokenValidationParameters.ClockSkew,
                async refresh =>
                {
                    if (refresh)
                    {
                        options.ConfigurationManager?.RequestRefresh();
                    }

                    var configuration = options.Configuration
                        ?? await options.ConfigurationManager!.GetConfigurationAsync(context.HttpContext.RequestAborted);
                    return [.. configuration.SigningKeys, .. options.TokenValidationParameters.IssuerSigningKeys ?? []];
                },
                logger);
        }

        Capture(context.HttpContext, scheme, idToken, accessToken, logger);
    }

    /// <summary>
    /// Records the verifiable claims of the tokens validated for this sign-in.
    /// </summary>
    /// <param name="context">The request completing the sign-in.</param>
    /// <param name="scheme">The authentication scheme that validated the token.</param>
    /// <param name="validatedToken">The validated identity token.</param>
    /// <param name="validatedAccessToken">The validated access token from the same code exchange, or <see langword="null"/> when it was absent or invalid.</param>
    /// <param name="logger">The logger.</param>
    internal static void Capture(HttpContext context, string scheme, SecurityToken? validatedToken, JsonWebToken? validatedAccessToken, ILogger? logger = null)
    {
        context.Items.Remove(ItemKey);
        if (validatedToken is not JsonWebToken jwt || validatedAccessToken is null)
        {
            return;
        }

        if (!TryRead(jwt.Claims, "sub", out var identitySubject)
            || !TryRead(validatedAccessToken.Claims, "sub", out var accessSubject)
            || !string.Equals((string)identitySubject, (string)accessSubject, StringComparison.Ordinal))
        {
            logger?.SubjectMismatch();
            return;
        }

        var values = new Dictionary<string, object>(StringComparer.Ordinal);
        foreach (var name in Names)
        {
            var source = _identityTokenClaims.Contains(name) ? jwt : validatedAccessToken;
            if (TryRead(source.Claims, name, out var value))
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

    /// <summary>
    /// The handler hands the validated identity token over as a JwtSecurityToken; its raw data is the exact compact
    /// serialization that was validated, so reading it again as a JsonWebToken reads the same, already-verified token.
    /// </summary>
    /// <param name="token">The validated token.</param>
    /// <returns>The token as a <see cref="JsonWebToken"/>, or <see langword="null"/> when it is neither kind.</returns>
    static JsonWebToken? AsJsonWebToken(SecurityToken? token)
    {
        try
        {
            return token switch
            {
                JsonWebToken jwt => jwt,
                JwtSecurityToken legacy => new JsonWebTokenHandler().ReadJsonWebToken(legacy.RawData),
                _ => null
            };
        }
        catch (Exception exception) when (exception is ArgumentException or SecurityTokenException)
        {
            return null;
        }
    }

    static bool TryRead(IEnumerable<Claim> claims, string name, out object value)
    {
        value = string.Empty;
        var matches = claims.Where(_ => string.Equals(_.Type, name, StringComparison.Ordinal)).Take(2).ToArray();
        if (matches.Length != 1)
        {
            return false;
        }

        var text = matches[0].Value;
        if (text.Length == 0 || text.Length > MaximumLength || !string.Equals(text, text.Trim(), StringComparison.Ordinal))
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
