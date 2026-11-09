// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.BearerRoutes;
using Cratis.AuthProxy.Configuration;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.SignIns;

/// <summary>
/// Fully validates the access token an OpenID Connect provider returned in the same authorization-code exchange
/// as the identity token, before any claim is read from it.
/// </summary>
/// <remarks>
/// The token is held only for the duration of the call: it is never stored, saved to a session or logged — a
/// refusal is logged by reason alone. The checks mirror a bearer route's: an exact issuer (the one the handler
/// already validated on the identity token), an audience of AuthProxy's own client or the configured resource,
/// a signature from the provider's published keys with an algorithm from <see cref="BearerRouteDefaults.AllowedAlgorithms"/>,
/// an RFC 9068 <c language="text">typ</c> header (<see cref="BearerIssuer.DefaultTokenTypes"/>) and an unexpired lifetime.
/// </remarks>
static class UpstreamAccessTokenValidator
{
    static readonly JsonWebTokenHandler _handler = new() { MapInboundClaims = false };

    /// <summary>
    /// Validates the access token.
    /// </summary>
    /// <param name="accessToken">The access token from the token endpoint response, if any.</param>
    /// <param name="idToken">The identity token the handler has already validated.</param>
    /// <param name="audiences">The audiences acceptable for the access token.</param>
    /// <param name="clockSkew">The permitted clock skew.</param>
    /// <param name="signingKeys">Gets the provider's signing keys; the argument asks for a fresh set after an unknown key.</param>
    /// <param name="logger">The logger.</param>
    /// <returns>The validated token, or <see langword="null"/> when it is absent or fails any check.</returns>
    internal static async Task<JsonWebToken?> Validate(
        string? accessToken,
        JsonWebToken idToken,
        IEnumerable<string> audiences,
        TimeSpan clockSkew,
        Func<bool, Task<IReadOnlyCollection<SecurityKey>>> signingKeys,
        ILogger logger)
    {
        if (string.IsNullOrWhiteSpace(accessToken))
        {
            logger.AccessTokenAbsent();
            return null;
        }

        var accepted = audiences.Where(_ => !string.IsNullOrWhiteSpace(_)).ToArray();
        if (string.IsNullOrEmpty(idToken.Issuer) || accepted.Length == 0)
        {
            logger.AccessTokenRefused("no issuer or audience to validate against");
            return null;
        }

        try
        {
            var result = await _handler.ValidateTokenAsync(accessToken, Parameters(idToken.Issuer, accepted, clockSkew, await signingKeys(false)));
            if (!result.IsValid && result.Exception is SecurityTokenSignatureKeyNotFoundException)
            {
                result = await _handler.ValidateTokenAsync(accessToken, Parameters(idToken.Issuer, accepted, clockSkew, await signingKeys(true)));
            }

            if (result.IsValid && result.SecurityToken is JsonWebToken validated)
            {
                return validated;
            }

            logger.AccessTokenRefused(result.Exception?.GetType().Name ?? "unknown");
        }
        catch (Exception exception) when (exception is ArgumentException or SecurityTokenException or InvalidOperationException or HttpRequestException)
        {
            logger.AccessTokenRefused(exception.GetType().Name);
        }

        return null;
    }

    static TokenValidationParameters Parameters(string issuer, string[] audiences, TimeSpan clockSkew, IReadOnlyCollection<SecurityKey> keys) => new()
    {
        ValidateIssuer = true,
        ValidIssuer = issuer,
        ValidateAudience = true,
        RequireAudience = true,
        IgnoreTrailingSlashWhenValidatingAudience = false,
        ValidAudiences = audiences,
        ValidateLifetime = true,
        RequireExpirationTime = true,
        ClockSkew = clockSkew,
        RequireSignedTokens = true,
        ValidateIssuerSigningKey = true,
        IssuerSigningKeys = keys,
        ValidAlgorithms = BearerRouteDefaults.AllowedAlgorithms,
        ValidTypes = BearerIssuer.DefaultTokenTypes,
        SaveSigninToken = false,
    };
}
