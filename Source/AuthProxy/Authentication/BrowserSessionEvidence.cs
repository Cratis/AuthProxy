// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using System.Security.Claims;
using Cratis.AuthProxy.ForwardedIdentity;
using Cratis.AuthProxy.OnBehalfSessions;
using Cratis.AuthProxy.SignIns;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>Evidence authored once at a verified Cratis Identity sign-in and protected with the cookie ticket.</summary>
/// <param name="CredentialId">The fresh cookie credential identifier.</param>
/// <param name="Scheme">The verified Cratis Identity registration.</param>
/// <param name="Person">The verified account and original authentication evidence.</param>
internal sealed record BrowserSessionEvidence(string CredentialId, string Scheme, ForwardedIdentityPersonEvidence Person)
{
    /// <summary>The cookie-protected evidence property.</summary>
    internal const string PropertyKey = ".cratis.browser-evidence.v2";

    /// <inheritdoc/>
    public override string ToString() => nameof(BrowserSessionEvidence);

    /// <summary>Creates a fresh browser credential, never a token identifier or callback timestamp.</summary>
    /// <param name="context">The sign-in request holding validated upstream evidence.</param>
    /// <param name="principal">The canonical completed principal.</param>
    /// <param name="properties">The protected cookie properties.</param>
    /// <param name="scheme">The validated OIDC scheme, or null for an OAuth completion.</param>
    internal static void Stamp(HttpContext context, ClaimsPrincipal principal, AuthenticationProperties properties, string? scheme)
    {
        properties.Items.Remove(PropertyKey);
        var provider = Provider(context, scheme);
        if (provider is null) return;
        var person = VerifiedPerson(VerifiedUpstreamClaims.For(context, scheme));
        if (person is null || !IsProvenPerson(provider, principal, properties, person)) return;
        properties.Items[PropertyKey] = JsonSerializer.Serialize(new BrowserSessionEvidence(Guid.NewGuid().ToString("D"), scheme!, person));
    }

    /// <summary>Reads only the selected cookie ticket, not a second credential on the request.</summary>
    /// <param name="context">The authenticated request.</param>
    /// <returns>Complete browser evidence, or null for every unsupported or incomplete credential.</returns>
    internal static ForwardedIdentityTrustedContext? For(HttpContext? context)
    {
        if (context?.User.Identity?.IsAuthenticated != true) return null;
        if (HasOtherCredential(context)) return null;
        var result = context.Features.Get<IAuthenticateResultFeature>()?.AuthenticateResult;
        if (result?.Succeeded != true) return null;
        if (result.Ticket.AuthenticationScheme != CookieAuthenticationDefaults.AuthenticationScheme) return null;
        return ReferenceEquals(context.User, result.Principal) ? Read(context, result.Principal, result.Properties) : null;
    }

    /// <summary>Reads a protected session snapshot, including during sign-in callback preparation.</summary>
    /// <param name="context">The request services validating the current registration.</param>
    /// <param name="principal">The cookie principal.</param>
    /// <param name="properties">The protected cookie properties.</param>
    /// <returns>Trusted browser evidence, or null.</returns>
    internal static ForwardedIdentityTrustedContext? Read(HttpContext context, ClaimsPrincipal principal, AuthenticationProperties? properties)
    {
        if (principal.Identity?.IsAuthenticated != true) return null;
        var evidence = Deserialize(properties?.GetString(PropertyKey));
        if (evidence?.Person is not { } person) return null;
        if (!IsCredentialId(evidence.CredentialId)) return null;
        if (!IsCurrentRegistration(context, properties!, evidence)) return null;
        if (!MatchesPerson(principal, properties!, person)) return null;
        if (CanonicalSessionPolicy.Evaluate(principal, properties, CookieAuthenticationDefaults.AuthenticationScheme, context.RequestServices) != CanonicalSessionVerdict.Current) return null;
        return new("browser-session", evidence.CredentialId, "none") { TrustedRealmIssuer = person.Issuer, Person = person };
    }

    static ForwardedIdentityPersonEvidence? VerifiedPerson(VerifiedUpstreamClaims? verified)
    {
        if (verified?.Values.TryGetValue("auth_time", out var authTime) != true || authTime is not long seconds) return null;
        var values = verified.Values;

        // Cookies are unbound browser credentials. Upstream tokens are never forwarded by this evidence;
        // arbitrary upstream acr/amr labels cannot elevate conservative basic assurance.
        return new(StringValue(values, "iss"), StringValue(values, "sub"), StringValue(values, "idp"), seconds.ToString(CultureInfo.InvariantCulture), "basic");
    }

    static string StringValue(IReadOnlyDictionary<string, object> values, string name) => values.TryGetValue(name, out var value) ? value as string ?? string.Empty : string.Empty;

    static bool HasOtherCredential(HttpContext context) => context.Request.Headers.ContainsKey("Authorization")
        || context.Request.Headers.ContainsKey("DPoP") || context.TryGetOnBehalf(out _);

    static bool IsProvenPerson(C.OidcProvider provider, ClaimsPrincipal principal, AuthenticationProperties properties, ForwardedIdentityPersonEvidence person)
    {
        if (!IsRealm(provider, person.Issuer)) return false;
        if (string.IsNullOrEmpty(person.IdentityProvider)) return false;
        return MatchesPerson(principal, properties, person);
    }

    static bool MatchesPerson(ClaimsPrincipal principal, AuthenticationProperties properties, ForwardedIdentityPersonEvidence person)
    {
        if (!HasClaim(principal, CanonicalIdentityClaims.Issuer, person.Issuer)) return false;
        if (!HasClaim(principal, CanonicalIdentityClaims.Subject, person.Subject)) return false;
        return SessionAuthenticationTime.TryRead(principal, properties, out var time) && person.AuthenticationTime == time.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
    }

    static bool IsCurrentRegistration(HttpContext context, AuthenticationProperties properties, BrowserSessionEvidence evidence)
    {
        if (properties.GetString(AuthenticationServiceCollectionExtensions.AuthenticationSchemeStateKey) != evidence.Scheme) return false;
        var provider = Provider(context, evidence.Scheme);
        return provider is not null && IsRealm(provider, evidence.Person.Issuer);
    }

    static BrowserSessionEvidence? Deserialize(string? json)
    {
        if (json is null || json.Length > 16384) return null;
        try
        {
            return JsonSerializer.Deserialize<BrowserSessionEvidence>(json);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    static bool IsCredentialId(string value) => Guid.TryParseExact(value, "D", out var id) && id != Guid.Empty;

    static C.OidcProvider? Provider(HttpContext context, string? scheme) => context.RequestServices.GetService<IOptionsMonitor<C.Authentication>>()?.CurrentValue.OidcProviders
        .SingleOrDefault(provider => CratisIdentityProfile.AppliesTo(provider) && OidcProviderScheme.FromName(provider.Name) == scheme);

    static bool IsRealm(C.OidcProvider provider, string issuer) => Uri.TryCreate(issuer, UriKind.Absolute, out var uri)
        && uri.Scheme == Uri.UriSchemeHttps && string.Equals(provider.Authority, issuer, StringComparison.Ordinal);

    static bool HasClaim(ClaimsPrincipal principal, string type, string value)
    {
        var claims = principal.FindAll(type).ToArray();
        return claims.Length == 1 && string.Equals(claims[0].Value, value, StringComparison.Ordinal);
    }
}
