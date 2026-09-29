// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers;
using System.Security.Claims;
using Cratis.AuthProxy.Authentication;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.BearerRoutes;

/// <summary>
/// Validates the access token presented on a bearer route and builds the principal AuthProxy forwards for it.
/// </summary>
/// <param name="metadata">The source of the issuers' signing keys.</param>
/// <remarks>
/// The token is checked strictly: the issuer must be one the route accepts and must match exactly; the signature
/// must verify against a key the issuer publishes, with an asymmetric algorithm from
/// <see cref="BearerRouteDefaults.AllowedAlgorithms"/> (so neither <c language="text">none</c> nor a symmetric algorithm keyed
/// with a public key is accepted); the <c language="text">typ</c> header must name an access token; the audience must be one
/// the route accepts; and the token must carry an expiry and be within its lifetime, allowing only the route's small
/// clock skew. Encrypted tokens are refused. Only then are scopes and tenant looked at.
/// </remarks>
public sealed class BearerTokenValidator(IBearerIssuerMetadata metadata) : IBearerTokenValidator
{
    /// <summary>
    /// The longest tenant identifier accepted from a token.
    /// </summary>
    public const int MaximumTenantIdLength = 256;

    const string BearerPrefix = "Bearer ";
    const string ScopeClaimType = "scope";
    const string SubjectClaimType = "sub";

    static readonly SearchValues<char> _tokenCharacters = SearchValues.Create(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/=");

    static readonly SearchValues<char> _tenantCharacters = SearchValues.Create(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~");

    static readonly JsonWebTokenHandler _handler = new() { MapInboundClaims = false };

    enum TokenPresence
    {
        Absent = 0,
        Present = 1,
        Malformed = 2,
    }

    /// <summary>
    /// Gets the scopes a route requires, trimmed and without blanks.
    /// </summary>
    /// <param name="route">The route.</param>
    /// <returns>The required scopes.</returns>
    public static IEnumerable<string> RequiredScopes(ResolvedBearerRoute route) =>
        route.Route.RequiredScopes
            .Where(_ => !string.IsNullOrWhiteSpace(_))
            .Select(_ => _.Trim())
            .Distinct(StringComparer.Ordinal);

    /// <summary>
    /// Reads the issuer a request's bearer token claims to come from, without validating anything.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <param name="issuer">The claimed issuer.</param>
    /// <returns><see langword="true"/> when the request carries a readable, unencrypted JWT naming an issuer; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// Only good for deciding which rules apply to a token, never for trusting it: nothing about the value has
    /// been checked.
    /// </remarks>
    public static bool TryReadPresentedIssuer(HttpRequest request, out string issuer)
    {
        issuer = string.Empty;
        return ReadBearerToken(request, out var token) == TokenPresence.Present
            && TryReadUnvalidatedIssuer(token, out issuer);
    }

    /// <inheritdoc/>
    public async Task<BearerTokenValidation> Validate(HttpRequest request, ResolvedBearerRoute route, CancellationToken cancellationToken)
    {
        var header = ReadBearerToken(request, out var token);
        if (header == TokenPresence.Absent)
        {
            return BearerTokenValidation.Refused(BearerTokenValidationStatus.Missing, "No bearer token was presented.");
        }

        if (header == TokenPresence.Malformed)
        {
            return BearerTokenValidation.Refused(BearerTokenValidationStatus.Invalid, "The authorization header is malformed.");
        }

        if (!TryReadUnvalidatedIssuer(token, out var presentedIssuer))
        {
            return BearerTokenValidation.Refused(BearerTokenValidationStatus.Invalid, "The token is not a signed JWT.");
        }

        var issuer = route.Issuers.FirstOrDefault(_ => string.Equals(_.Issuer, presentedIssuer, StringComparison.Ordinal));
        if (issuer is null)
        {
            return BearerTokenValidation.Refused(BearerTokenValidationStatus.Invalid, "The token's issuer is not accepted on this route.");
        }

        var keys = await metadata.GetSigningKeys(issuer, cancellationToken);
        if (keys is null)
        {
            return BearerTokenValidation.Refused(BearerTokenValidationStatus.IssuerUnavailable, "The issuer's signing keys are unavailable.");
        }

        var result = await _handler.ValidateTokenAsync(token, CreateParameters(route, issuer, keys));
        if (!result.IsValid && result.Exception is SecurityTokenSignatureKeyNotFoundException)
        {
            // The token names a key this proxy has not seen — the issuer may have rotated. Ask for fresh keys once;
            // refreshes are rate limited, so this cannot be turned into a flood of requests to the issuer.
            metadata.RequestRefresh(issuer);
            keys = await metadata.GetSigningKeys(issuer, cancellationToken);
            if (keys is null)
            {
                return BearerTokenValidation.Refused(BearerTokenValidationStatus.IssuerUnavailable, "The issuer's signing keys are unavailable.");
            }

            result = await _handler.ValidateTokenAsync(token, CreateParameters(route, issuer, keys));
        }

        if (!result.IsValid || result.ClaimsIdentity is null)
        {
            return BearerTokenValidation.Refused(
                BearerTokenValidationStatus.Invalid,
                $"The token failed validation ({result.Exception?.GetType().Name ?? "unknown"}).");
        }

        var claims = result.ClaimsIdentity.Claims.ToArray();
        var scopes = claims
            .Where(_ => string.Equals(_.Type, ScopeClaimType, StringComparison.Ordinal))
            .SelectMany(_ => _.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        var missingScopes = RequiredScopes(route).Where(_ => !scopes.Contains(_, StringComparer.Ordinal)).ToArray();
        if (missingScopes.Length > 0)
        {
            return BearerTokenValidation.Refused(
                BearerTokenValidationStatus.InsufficientScope,
                $"The token lacks the required scope(s) {string.Join(' ', missingScopes)}.");
        }

        if (!TryGetSingleValue(claims, route.TenantClaimType, out var tenantId) || !IsUsableTenantId(tenantId))
        {
            return BearerTokenValidation.Refused(
                BearerTokenValidationStatus.MissingTenant,
                $"The token carries no single usable '{route.TenantClaimType}' claim.");
        }

        if (!TryGetSingleValue(claims, SubjectClaimType, out var subject))
        {
            return BearerTokenValidation.Refused(BearerTokenValidationStatus.Invalid, "The token carries no single subject.");
        }

        if (!TryBuildForwardedClaims(route, claims, out var forwarded, out var missingSource))
        {
            return BearerTokenValidation.Refused(
                BearerTokenValidationStatus.Invalid,
                $"The token carries no '{missingSource}' claim for a configured claim mapping.");
        }

        forwarded.Add(new Claim(BearerRouteClaims.Issuer, issuer.Issuer));
        forwarded.Add(new Claim(BearerRouteClaims.Subject, subject));
        if (TryGetSingleValue(claims, "azp", out var clientId) || TryGetSingleValue(claims, "client_id", out clientId))
        {
            forwarded.Add(new Claim(BearerRouteClaims.ClientId, clientId));
        }

        forwarded.AddRange(scopes.Select(_ => new Claim(BearerRouteClaims.Scope, _)));

        var identity = new ClaimsIdentity(forwarded, route.IdentityProvider, "name", ClaimTypes.Role);
        return BearerTokenValidation.Success(new ClaimsPrincipal(identity), tenantId);
    }

    static TokenValidationParameters CreateParameters(ResolvedBearerRoute route, ResolvedBearerIssuer issuer, IReadOnlyCollection<SecurityKey> keys) => new()
    {
        ValidateIssuer = true,
        ValidIssuer = issuer.Issuer,
        ValidateAudience = true,
        RequireAudience = true,
        ValidAudiences = route.Route.Audiences.Where(_ => !string.IsNullOrWhiteSpace(_)).Select(_ => _.Trim()).ToArray(),
        ValidateLifetime = true,
        RequireExpirationTime = true,
        ClockSkew = route.ClockSkew,
        RequireSignedTokens = true,
        ValidateIssuerSigningKey = true,
        IssuerSigningKeys = keys,
        ValidAlgorithms = BearerRouteDefaults.AllowedAlgorithms,
        ValidTypes = issuer.TokenTypes,
        SaveSigninToken = false,
    };

    static TokenPresence ReadBearerToken(HttpRequest request, out string token)
    {
        token = string.Empty;

        var values = request.Headers.Authorization;
        if (values.Count == 0)
        {
            return TokenPresence.Absent;
        }

        if (values.Count != 1 || values[0] is not { } value)
        {
            return TokenPresence.Malformed;
        }

        // Another scheme is not a bearer token at all, which RFC 6750 answers with a bare challenge.
        if (!value.StartsWith(BearerPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return TokenPresence.Absent;
        }

        token = value[BearerPrefix.Length..];
        return token.Length > 0 && token.AsSpan().IndexOfAnyExcept(_tokenCharacters) < 0
            ? TokenPresence.Present
            : TokenPresence.Malformed;
    }

    static bool TryReadUnvalidatedIssuer(string token, out string issuer)
    {
        issuer = string.Empty;
        if (!_handler.CanReadToken(token))
        {
            return false;
        }

        try
        {
            var jwt = _handler.ReadJsonWebToken(token);
            if (jwt.IsEncrypted || string.IsNullOrEmpty(jwt.Issuer))
            {
                return false;
            }

            issuer = jwt.Issuer;
            return true;
        }
        catch (Exception exception) when (exception is ArgumentException or SecurityTokenException or JsonException)
        {
            return false;
        }
    }

    static bool TryGetSingleValue(IEnumerable<Claim> claims, string claimType, out string value)
    {
        var values = claims.Where(_ => string.Equals(_.Type, claimType, StringComparison.Ordinal)).Take(2).ToArray();
        value = values.Length == 1 ? values[0].Value.Trim() : string.Empty;
        return value.Length > 0;
    }

    static bool IsUsableTenantId(string tenantId) =>
        tenantId.Length <= MaximumTenantIdLength && tenantId.AsSpan().IndexOfAnyExcept(_tenantCharacters) < 0;

    static bool TryBuildForwardedClaims(ResolvedBearerRoute route, Claim[] tokenClaims, out List<Claim> forwarded, out string missingSource)
    {
        missingSource = string.Empty;

        // AuthProxy's own namespaces are written by AuthProxy alone. A token that carries them does not get to
        // speak for the proxy: canonical identity claims would make the forwarded principal unbuildable, and
        // bearer-route claims would claim a client or scope the token was not validated for.
        // Role claims are dropped too: the issuer vouches for who the caller is and what the client may attempt,
        // and the forwarded principal carries no role the backend did not grant itself.
        forwarded = [.. tokenClaims
            .Where(_ => !CanonicalIdentityClaims.IsReserved(_.Type) && !BearerRouteClaims.IsReserved(_.Type) && !IsRoleClaim(_.Type))
            .Select(_ => new Claim(_.Type, _.Value, _.ValueType))];

        foreach (var (target, source) in route.Route.ClaimMappings)
        {
            var values = tokenClaims
                .Where(_ => string.Equals(_.Type, source, StringComparison.Ordinal))
                .Select(_ => _.Value)
                .Where(_ => !string.IsNullOrWhiteSpace(_))
                .ToArray();
            if (values.Length == 0)
            {
                missingSource = source;
                return false;
            }

            forwarded.RemoveAll(_ => string.Equals(_.Type, target, StringComparison.Ordinal));
            forwarded.AddRange(values.Select(_ => new Claim(target, _)));
        }

        return true;
    }

    static bool IsRoleClaim(string claimType) =>
        string.Equals(claimType, ClaimTypes.Role, StringComparison.Ordinal)
        || string.Equals(claimType, "role", StringComparison.Ordinal)
        || string.Equals(claimType, "roles", StringComparison.Ordinal);
}
