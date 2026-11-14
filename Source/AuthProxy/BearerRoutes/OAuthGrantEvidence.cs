// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using Cratis.AuthProxy.BearerRoutes.Introspection;
using Cratis.AuthProxy.ForwardedIdentity;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.BearerRoutes;

/// <summary>Produces v2 evidence only for a locally verified, actively introspected first-party OAuth grant.</summary>
/// <param name="route">The selected trusted route.</param>
/// <param name="now">The current instant.</param>
internal sealed class OAuthGrantEvidence(ResolvedBearerRoute route, DateTimeOffset now)
{
    /// <summary>Builds evidence from the exact verified JWT, before any presentation claim mappings.</summary>
    /// <param name="token">The strict bearer token that passed local signature validation.</param>
    /// <param name="validation">The successful local validation.</param>
    /// <param name="activity">The narrowed introspection evidence.</param>
    /// <returns>The trusted evidence, or null when the grant cannot be vouched for.</returns>
    internal ForwardedIdentityTrustedContext? Create(string token, BearerTokenValidation validation, IntrospectionResult activity)
    {
        if (!CanVouchFor(validation, activity) || ClientCredentialsOnBearerRoutes.CouldBeIssued(token)) return null;
        try
        {
            var parts = token.Split('.');
            if (parts.Length != 3 || parts[2].Length == 0) return null;
            using var document = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(parts[1]));
            return FromVerifiedClaims(document.RootElement, token, validation, activity);
        }
        catch (Exception error) when (error is JsonException or FormatException or ArgumentException or InvalidOperationException)
        {
            return null;
        }
    }

    static bool IsUnambiguousGrant(JsonElement claims) => claims.ValueKind == JsonValueKind.Object
        && claims.EnumerateObject().Select(field => field.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == claims.EnumerateObject().Count()
        && !claims.EnumerateObject().Any(field => field.Name.Equals("act", StringComparison.OrdinalIgnoreCase) || field.Name.Equals("grant_id", StringComparison.OrdinalIgnoreCase) || field.Name.Equals("cnf", StringComparison.OrdinalIgnoreCase));

    static string Text(JsonElement claims, string name) => claims.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString()! : string.Empty;

    static bool MatchesIdentity(JsonElement claims, BearerTokenValidation validation) => Text(claims, "iss") == validation.Issuer!.Issuer
        && Text(claims, "sub") == validation.Principal?.FindFirst(BearerRouteClaims.Subject)?.Value;

    static string? AuthenticationMethods(JsonElement claims) => claims.TryGetProperty("amr", out var methods)
        ? Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(methods.GetRawText())) : null;

    static ForwardedIdentityPersonEvidence? Person(JsonElement claims)
    {
        if (NumericDate(claims, "auth_time") is not { } seconds) return null;
        return new(Text(claims, "iss"), Text(claims, "sub"), Text(claims, "idp"), seconds.ToString(CultureInfo.InvariantCulture), Text(claims, "acr"));
    }

    static long? NumericDate(JsonElement claims, string name) => claims.TryGetProperty(name, out var value) && value.TryGetInt64(out var seconds) ? seconds : null;

    static bool IsCanonicalCredential(IntrospectionCredential? credential) => credential is not null
        && Guid.TryParseExact(credential.CredentialId, "D", out var id) && id.ToString("D") == credential.CredentialId;

    static string? PolicyEpoch(IntrospectionResult activity) => ulong.TryParse(activity.Credential!.Epoch, NumberStyles.None, CultureInfo.InvariantCulture, out var epoch)
        ? epoch.ToString(CultureInfo.InvariantCulture) : null;

    static bool MatchesCredential(JsonElement claims, IntrospectionResult activity) => !claims.TryGetProperty("cid", out var cid)
        || (cid.ValueKind == JsonValueKind.String && cid.GetString() == activity.Credential!.CredentialId);

    bool CanVouchFor(BearerTokenValidation validation, IntrospectionResult activity)
    {
        if (!validation.Succeeded || !route.Route.ForwardAuthorizationHeader) return false;
        return IsUnbound(validation) && HasFreshCredential(activity) && IsTrustedIssuer(validation.Issuer);
    }

    bool IsUnbound(BearerTokenValidation validation) => validation.SenderConstraint is null
        && validation.SenderBinding == "none" && route.Route.Dpop is null;

    bool HasFreshCredential(IntrospectionResult activity) => activity.Verdict == IntrospectionVerdict.Active
        && IsCanonicalCredential(activity.Credential) && activity.ValidUntil is { } deadline && deadline > now;

    bool IsTrustedIssuer(ResolvedBearerIssuer? issuer) => issuer is { Introspection: not null }
        && route.Issuers.Any(candidate => candidate.Issuer == issuer.Issuer);

    DateTimeOffset? Expiration(JsonElement claims, IntrospectionResult activity)
    {
        if (NumericDate(claims, "exp") is not { } seconds) return null;
        var expires = DateTimeOffset.FromUnixTimeSeconds(seconds);
        if (activity.ExpiresAt is { } activityExpiration && activityExpiration < expires) expires = activityExpiration;
        if (activity.ValidUntil is { } deadline && deadline < expires) expires = deadline;
        return expires > now ? expires : null;
    }

    ForwardedIdentityTrustedContext? FromVerifiedClaims(JsonElement claims, string token, BearerTokenValidation validation, IntrospectionResult activity)
    {
        if (!IsUnambiguousGrant(claims)) return null;
        if (!MatchesIdentity(claims, validation)) return null;
        if (!MatchesCredential(claims, activity)) return null;
        if (Person(claims) is not { } person) return null;
        if (Expiration(claims, activity) is not { } expires) return null;
        var context = new ForwardedIdentityTrustedContext("oauth-grant", activity.Credential!.CredentialId, "none")
        {
            TrustedRealmIssuer = validation.Issuer!.Issuer,
            Person = person,
            AuthenticationMethods = AuthenticationMethods(claims),
            Bearer = new(token, "oauth-verifier", person.Issuer, person.Subject),
            SnapshotExpiresUtc = expires,
            PolicyEpoch = PolicyEpoch(activity)
        };
        return ForwardedIdentityV2ContextHeaders.TryHeaders(context, out _) ? context : null;
    }
}
