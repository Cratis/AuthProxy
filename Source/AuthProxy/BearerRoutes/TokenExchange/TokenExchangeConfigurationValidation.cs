// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.BearerRoutes.TokenExchange;

/// <summary>Validates only trusted operator settings, never request-derived values.</summary>
internal static class TokenExchangeConfigurationValidation
{
    /// <summary>Collects route exchange configuration failures without including credentials.</summary>
    /// <param name="route">The trusted route configuration.</param>
    /// <param name="location">The safe configuration location.</param>
    /// <param name="failures">The validation failures.</param>
    internal static void Validate(C.BearerRoute route, string location, List<string> failures)
    {
        if (route.TokenExchange is not { } exchange) return;
        Require(route.Dpop is null, $"{location} cannot combine TokenExchange and Dpop.", failures);
        ValidateAuthority(exchange, location, failures);
        ValidateResult(route, exchange, location, failures);
        ValidateBounds(exchange, location, failures);
        ValidateIssuers(route, exchange, location, failures);
    }

    /// <summary>Requires an absolute HTTPS endpoint with no user information, query or fragment.</summary>
    /// <param name="value">The configured endpoint.</param>
    /// <returns>Whether the endpoint syntax is admitted.</returns>
    internal static bool IsEndpoint(string value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps && IsPlainUri(uri);

    static bool IsPlainUri(Uri uri) => uri.UserInfo.Length == 0 && uri.Query.Length == 0 && uri.Fragment.Length == 0;

    static bool IsResource(string value) => value.Length <= 2048 && Uri.IsWellFormedUriString(value, UriKind.Absolute)
        && Uri.TryCreate(value, UriKind.Absolute, out var uri) && IsResourceUri(uri);

    static bool IsResourceUri(Uri uri) => (uri.Scheme == "https" || uri.Scheme == "urn") && IsPlainUri(uri);

    static bool IsScope(string scope) => !string.IsNullOrWhiteSpace(scope) && !scope.Any(char.IsWhiteSpace) && scope != "offline_access";

    static void Require(bool valid, string message, List<string> failures)
    {
        if (!valid) failures.Add(message);
    }

    static void ValidateAuthority(C.BearerTokenExchange exchange, string location, List<string> failures)
    {
        Require(IsEndpoint(exchange.Endpoint), $"{location} TokenExchange requires an HTTPS endpoint without credentials, query or fragment.", failures);
        Require(!string.IsNullOrWhiteSpace(exchange.ClientId) && !string.IsNullOrWhiteSpace(exchange.ClientSecret), $"{location} TokenExchange requires client credentials.", failures);
        Require(IsResource(exchange.Resource), $"{location} TokenExchange requires an absolute HTTPS or URN Resource.", failures);
    }

    static void ValidateResult(C.BearerRoute route, C.BearerTokenExchange exchange, string location, List<string> failures)
    {
        Require(!string.IsNullOrWhiteSpace(exchange.Audience) && route.Audiences.Contains(exchange.Audience, StringComparer.Ordinal), $"{location} TokenExchange Audience must be a route audience.", failures);
        Require(!string.IsNullOrWhiteSpace(exchange.ResultIssuer) && route.Issuers.Any(_ => _.Issuer == exchange.ResultIssuer), $"{location} TokenExchange ResultIssuer must be a route issuer.", failures);
    }

    static void ValidateBounds(C.BearerTokenExchange exchange, string location, List<string> failures)
    {
        Require(exchange.Scopes.Count > 0 && exchange.Scopes.All(IsScope), $"{location} TokenExchange requires explicit non-offline scopes.", failures);
        Require(exchange.Timeout >= TimeSpan.FromMilliseconds(100) && exchange.Timeout <= TimeSpan.FromSeconds(10), $"{location} TokenExchange Timeout must be between 100 milliseconds and 10 seconds.", failures);
        Require(exchange.MaximumCachedTokens is >= 1 and <= 1000000, $"{location} TokenExchange MaximumCachedTokens must be between 1 and 1000000.", failures);
    }

    static void ValidateIssuers(C.BearerRoute route, C.BearerTokenExchange exchange, string location, List<string> failures)
    {
        Require(exchange.Issuers.Count > 0, $"{location} TokenExchange requires external issuers.", failures);
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var issuer in exchange.Issuers)
        {
            Require(IsEndpoint(issuer.Issuer) && names.Add(issuer.Issuer), $"{location} TokenExchange issuers must be unique absolute HTTPS issuers.", failures);
            Require(!route.Issuers.Any(_ => _.Issuer == issuer.Issuer), $"{location} TokenExchange issuers cannot also be route issuers.", failures);
            Require(issuer.SubjectTokenType == "jwt" || issuer.SubjectTokenType == "access_token", $"{location} TokenExchange SubjectTokenType must be jwt or access_token.", failures);
        }
    }
}
