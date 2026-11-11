// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers;
using Cratis.AuthProxy.Authentication;
using Cratis.AuthProxy.BearerRoutes.PersonalAccessTokens;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.BearerRoutes;

/// <summary>
/// Refuses a configuration declaring a bearer route AuthProxy could not enforce as written.
/// </summary>
/// <remarks>
/// A route that cannot be resolved is left out of <see cref="BearerRouteTable"/>, which leaves its path on the
/// browser-session model. That is closed, but invisibly so: the operator believes a token-authenticated API is
/// being served and every client gets a sign-in redirect. Every such mistake is named here, at startup, instead.
/// </remarks>
public class BearerRouteConfigurationValidator : IValidateOptions<C.AuthProxy>
{
    /// <summary>
    /// The RFC 6749 §3.3 scope-token characters: %x21 / %x23-5B / %x5D-7E. Excluding the quote and the backslash
    /// also keeps every scope safe to quote in a <c language="text">WWW-Authenticate</c> parameter.
    /// </summary>
    static readonly SearchValues<char> _scopeCharacters = SearchValues.Create(
        "!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~");

    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, C.AuthProxy options)
    {
        List<string> failures = [];
        var prefixes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var metadataPaths = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var anonymousPaths = options.Services.Values.SelectMany(AnonymousPaths.For).ToArray();
        var state = new ValidationState(prefixes, metadataPaths, anonymousPaths, failures);

        foreach (var (serviceName, service) in options.Services)
        {
            ValidateService(serviceName, service, options, state);
        }

        // Check after collecting every prefix so declaration order and service ownership cannot hide a conflict.
        ValidateMetadataPaths(state);
        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    static void ValidateService(string serviceName, C.Service service, C.AuthProxy options, ValidationState state)
    {
        for (var index = 0; index < service.BearerRoutes.Count; index++)
        {
            var route = service.BearerRoutes[index];
            var at = $"{C.AuthProxy.SectionKey}:{nameof(C.AuthProxy.Services)}:{serviceName}:{nameof(C.Service.BearerRoutes)}:{index}";
            var location = new RouteLocation(at, serviceName);
            ValidateRoute(location, service, route, state);
            ValidateEnvironment(location, route, options.CredentialBinding, state.Failures);
            Dpop.DpopConfiguration.Validate(route, options, at, state.Failures);
            ValidateServicePath(location, service, state.Failures);
            ValidateServiceOverlaps(location, route, options, state.Failures);
            ValidateIdentityVerification(location, route, options, state.Failures);
        }
    }

    static void ValidateServicePath(RouteLocation location, C.Service service, List<string> failures)
    {
        var at = location.At;
        if (service.StripPathPrefix)
        {
            failures.Add(
                $"{at}: bearer routes cannot be used with {nameof(C.Service.StripPathPrefix)}. " +
                "A browser-session path with the service prefix removed could reach the same backend resource without the bearer policy. " +
                $"Set {nameof(C.Service.StripPathPrefix)} to false and serve the full external path at the backend, or remove the bearer routes.");
        }
    }

    static void ValidateServiceOverlaps(RouteLocation location, C.BearerRoute route, C.AuthProxy options, List<string> failures)
    {
        var at = location.At;
        var serviceName = location.ServiceName;
        if (AnonymousPathPolicy.Evaluate(route.PathPrefix, out var prefix) != AnonymousPathRejection.None)
        {
            return;
        }

        foreach (var (otherName, otherService) in options.Services.Where(_ => !string.Equals(_.Key, serviceName, StringComparison.OrdinalIgnoreCase)))
        {
            if (AnonymousPathPolicy.Evaluate(otherService.PathPrefix, out var otherPrefix) == AnonymousPathRejection.None
                && Overlaps(prefix, otherPrefix))
            {
                failures.Add(
                    $"{at}:{nameof(C.BearerRoute.PathPrefix)} '{prefix}' overlaps service '{otherName}' {nameof(C.Service.PathPrefix)} '{otherPrefix}'. " +
                    "Bearer routes claim their paths on every host; use non-overlapping prefixes.");
            }
        }

        failures.AddRange(ClientCredentialsOverlaps(serviceName, prefix, options).Select(conflict => $"{at}:{nameof(C.BearerRoute.PathPrefix)} '{prefix}' {conflict}"));
    }

    static void ValidateIdentityVerification(RouteLocation location, C.BearerRoute route, C.AuthProxy options, List<string> failures)
    {
        var at = location.At;
        if (options.RequiresIdentityVerification && !route.AcceptWithoutIdentityVerification)
        {
            failures.Add(
                $"{at}: the deployment requires identity verification ({nameof(C.IdentityVerificationMode)}.{nameof(C.IdentityVerificationMode.Required)}), " +
                "which a bearer route does not perform: it has no browser session to verify through /.cratis/me. Set " +
                $"{nameof(C.BearerRoute.AcceptWithoutIdentityVerification)} on the route to accept its callers on the token and " +
                "the claim requirements alone, or remove the route.");
        }
    }

    static void ValidateMetadataPaths(ValidationState state)
    {
        foreach (var metadataPath in state.MetadataPaths.Keys)
        {
            var conflictingPrefix = state.Prefixes.Keys.FirstOrDefault(_ => new PathString(metadataPath).StartsWithSegments(_, StringComparison.OrdinalIgnoreCase));
            if (conflictingPrefix is not null)
            {
                state.Failures.Add($"{nameof(C.BearerRoute.ResourceMetadataUrl)} path '{metadataPath}' is under bearer route '{conflictingPrefix}'. Resource metadata is forwarded without authentication and must be outside every bearer route.");
            }
        }
    }

    static IEnumerable<string> ClientCredentialsOverlaps(string serviceName, string prefix, C.AuthProxy options) =>
        options.Services
            .Where(other => other.Value.ClientCredentials is not null)
            .Select(other => ClientCredentialsOnBearerRoutes.Conflict(serviceName, prefix, other.Key, other.Value.ClientCredentials!))
            .OfType<string>();

    static void ValidateEnvironment(RouteLocation location, C.BearerRoute route, C.CredentialBinding binding, List<string> failures)
    {
        var at = location.At;
        if (route.EnvironmentClaimType.Length == 0) return;
        if (string.IsNullOrWhiteSpace(route.EnvironmentClaimType) || route.EnvironmentClaimType != route.EnvironmentClaimType.Trim())
        {
            failures.Add($"{at}:{nameof(C.BearerRoute.EnvironmentClaimType)} must be non-whitespace and have no surrounding whitespace.");
        }
        if (binding.Environment.Length == 0)
        {
            failures.Add($"{at}:{nameof(C.BearerRoute.EnvironmentClaimType)} requires {C.AuthProxy.SectionKey}:CredentialBinding:Environment.");
        }
    }

    static void ValidateRoute(RouteLocation location, C.Service service, C.BearerRoute route, ValidationState state)
    {
        var failures = state.Failures;
        ValidateBackend(location, service, failures);
        ValidatePathPrefix(location, route, state);
        ValidatePersonalAccessTokens(location, route, failures);
        ValidateIssuers(location, route, failures);
        ValidateAudience(location, route, failures);
        ValidateScopes(location, route, failures);
        ValidateResourceMetadata(location, route, state);
        ValidateIntrospection(location, route, failures);
        ValidateClockSkew(location, route, failures);
        ValidateRequiredClaims(location, route, failures);
        ValidateClaimMappings(location, route, failures);
    }

    static void ValidateBackend(RouteLocation location, C.Service service, List<string> failures)
    {
        var at = location.At;
        if (service.Backend is null || string.IsNullOrWhiteSpace(service.Backend.BaseUrl))
        {
            failures.Add($"{at}: the service declares no backend, so a bearer route has nothing to forward to.");
        }
    }

    static void ValidatePathPrefix(RouteLocation location, C.BearerRoute route, ValidationState state)
    {
        var at = location.At;
        var serviceName = location.ServiceName;
        var failures = state.Failures;
        var prefixes = state.Prefixes;
        var rejection = AnonymousPathPolicy.Evaluate(route.PathPrefix, out var prefix);
        if (rejection != AnonymousPathRejection.None)
        {
            failures.Add($"{at}:{nameof(C.BearerRoute.PathPrefix)} '{route.PathPrefix}' is not usable ({rejection}).");
            return;
        }

        if (!prefixes.TryAdd(prefix, serviceName))
        {
            failures.Add($"{at}:{nameof(C.BearerRoute.PathPrefix)} '{prefix}' is already a bearer route of service '{prefixes[prefix]}'.");
        }

        var overlapping = state.AnonymousPaths.FirstOrDefault(_ => Overlaps(_, prefix));
        if (overlapping is not null)
        {
            failures.Add($"{at}:{nameof(C.BearerRoute.PathPrefix)} '{prefix}' overlaps the anonymous path '{overlapping}'. A path cannot be both.");
        }
    }

    static void ValidateIssuers(RouteLocation location, C.BearerRoute route, List<string> failures)
    {
        var at = location.At;
        if (route.Issuers.Count == 0 && route.PersonalAccessTokens is null)
        {
            failures.Add($"{at}:{nameof(C.BearerRoute.Issuers)} is empty. A bearer route must name the authorization server whose tokens it accepts, or declare {nameof(C.BearerRoute.PersonalAccessTokens)}.");
        }

        for (var i = 0; i < route.Issuers.Count; i++)
        {
            if (!BearerRouteTable.TryResolveIssuer(route.Issuers[i], out _))
            {
                failures.Add(
                    $"{at}:{nameof(C.BearerRoute.Issuers)}:{i}: the issuer and its metadata address must be absolute HTTPS URIs without query, " +
                    "fragment or user information (plain HTTP is accepted only on a loopback host, and then for both).");
            }
        }
    }

    static void ValidateAudience(RouteLocation location, C.BearerRoute route, List<string> failures)
    {
        var at = location.At;
        var acceptsTokensOnly = route.Issuers.Count == 0 && route.PersonalAccessTokens is not null;
        if (!acceptsTokensOnly && route.Audiences.All(string.IsNullOrWhiteSpace))
        {
            failures.Add($"{at}:{nameof(C.BearerRoute.Audiences)} is empty. A bearer route must name the audience its tokens are issued for.");
        }
    }

    static void ValidateScopes(RouteLocation location, C.BearerRoute route, List<string> failures)
    {
        var at = location.At;
        foreach (var scope in route.RequiredScopes.Where(_ => !string.IsNullOrWhiteSpace(_)).Select(_ => _.Trim()))
        {
            if (scope.AsSpan().IndexOfAnyExcept(_scopeCharacters) >= 0)
            {
                failures.Add($"{at}:{nameof(C.BearerRoute.RequiredScopes)} '{scope}' is not a valid OAuth scope.");
            }
        }
    }

    static void ValidateClockSkew(RouteLocation location, C.BearerRoute route, List<string> failures)
    {
        var at = location.At;
        if (route.ClockSkew is { } skew && IsClockSkewOutsideBounds(skew))
        {
            failures.Add($"{at}:{nameof(C.BearerRoute.ClockSkew)} must be between zero and {C.BearerRoute.MaximumClockSkew}.");
        }
    }

    static bool IsClockSkewOutsideBounds(TimeSpan skew) =>
        skew < TimeSpan.Zero || skew > C.BearerRoute.MaximumClockSkew;

    static void ValidateRequiredClaims(RouteLocation location, C.BearerRoute route, List<string> failures)
    {
        var at = location.At;
        for (var i = 0; i < route.RequiredClaims.Count; i++)
        {
            var claim = route.RequiredClaims[i].Claim?.Trim();
            if (string.IsNullOrEmpty(claim))
            {
                failures.Add(
                    $"{at}:{nameof(C.BearerRoute.RequiredClaims)}:{i}:{nameof(C.ClaimRequirement.Claim)} must name a claim type. " +
                    "A requirement without one can never be satisfied and would refuse every token.");
            }
            else if (RoleClaims.Is(claim))
            {
                failures.Add(
                    $"{at}:{nameof(C.BearerRoute.RequiredClaims)}:{i} requires the role claim '{claim}', which a bearer token never carries: " +
                    "AuthProxy drops role claims from every token, so the requirement would refuse every token.");
            }
        }
    }

    static void ValidateClaimMappings(RouteLocation location, C.BearerRoute route, List<string> failures)
    {
        var at = location.At;
        var mappingTargets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var tenantClaim = string.IsNullOrWhiteSpace(route.TenantClaimType) ? C.BearerRoute.DefaultTenantClaimType : route.TenantClaimType.Trim();
        foreach (var (target, source) in route.ClaimMappings)
        {
            if (string.IsNullOrWhiteSpace(target) || string.IsNullOrWhiteSpace(source))
            {
                failures.Add($"{at}:{nameof(C.BearerRoute.ClaimMappings)} has a mapping with an empty claim type.");
            }
            else if (IsOwnedClaimType(target))
            {
                failures.Add($"{at}:{nameof(C.BearerRoute.ClaimMappings)} may not write '{target}': AuthProxy owns that claim type.");
            }
            else if (string.Equals(target, tenantClaim, StringComparison.OrdinalIgnoreCase))
            {
                failures.Add($"{at}:{nameof(C.BearerRoute.ClaimMappings)} may not write '{target}': the tenant must remain the token's original tenant claim.");
            }

            if (!mappingTargets.Add(target))
            {
                failures.Add($"{at}:{nameof(C.BearerRoute.ClaimMappings)} has conflicting targets differing only by case: '{target}'.");
            }
        }
    }

    static bool IsOwnedClaimType(string target) =>
        CanonicalIdentityClaims.IsReserved(target) || BearerRouteClaims.IsReserved(target) || RoleClaims.Is(target);

    static void ValidatePersonalAccessTokens(RouteLocation location, C.BearerRoute route, List<string> failures)
    {
        var at = location.At;
        if (route.PersonalAccessTokens is not { } tokens)
        {
            return;
        }

        if (!PersonalAccessTokenClassifier.IsValidResourceKey(tokens.ResourceKey))
        {
            failures.Add(
                $"{at}:{nameof(C.BearerRoute.PersonalAccessTokens)}:{nameof(C.BearerRoutePersonalAccessTokens.ResourceKey)} must be 'direct', 'studio' or 'stage-<app-key>' " +
                "with a lowercase letter, digit or hyphen app key.");
        }

        if (route.Issuers.Count == 0 && !string.IsNullOrWhiteSpace(route.ResourceMetadataUrl))
        {
            failures.Add($"{at}:{nameof(C.BearerRoute.ResourceMetadataUrl)} is set on a route that accepts personal access tokens only, which has no OAuth metadata to advertise.");
        }
    }

    static void ValidateIntrospection(RouteLocation location, C.BearerRoute route, List<string> failures)
    {
        var at = location.At;
        if (route.IntrospectionUnavailable == C.IntrospectionFailurePolicy.Accept && BearerRouteTable.IsMcpPrefix(route.PathPrefix))
        {
            failures.Add(
                $"{at}:{nameof(C.BearerRoute.IntrospectionUnavailable)} cannot be {nameof(C.IntrospectionFailurePolicy.Accept)} on an MCP route: " +
                "a revoked token must never be accepted because the issuer could not be asked.");
        }

        for (var i = 0; i < route.Issuers.Count; i++)
        {
            if (route.Issuers[i].Introspection is not { } introspection)
            {
                continue;
            }

            var issuerAt = $"{at}:{nameof(C.BearerRoute.Issuers)}:{i}:{nameof(C.BearerIssuer.Introspection)}";
            ValidateIssuerIntrospection(issuerAt, introspection, failures);
        }
    }

    static void ValidateIssuerIntrospection(string issuerAt, C.BearerIssuerIntrospection introspection, List<string> failures)
    {
        if (!BearerRouteTable.TryParseAuthorityUri(introspection.Endpoint, out _, out _))
        {
            failures.Add(
                $"{issuerAt}:{nameof(C.BearerIssuerIntrospection.Endpoint)} must be an absolute HTTPS URI without query, " +
                "fragment or user information (plain HTTP is accepted only on a loopback host).");
        }

        if (string.IsNullOrWhiteSpace(introspection.ClientId) || string.IsNullOrEmpty(introspection.ClientSecret))
        {
            failures.Add($"{issuerAt}: {nameof(C.BearerIssuerIntrospection.ClientId)} and {nameof(C.BearerIssuerIntrospection.ClientSecret)} are required.");
        }

        ValidateIntrospectionTimings(issuerAt, introspection, failures);

        if (introspection.MaximumCachedTokens < 1)
        {
            failures.Add($"{issuerAt}:{nameof(C.BearerIssuerIntrospection.MaximumCachedTokens)} must be at least 1.");
        }
    }

    static void ValidateIntrospectionTimings(string issuerAt, C.BearerIssuerIntrospection introspection, List<string> failures)
    {
        if (introspection.CacheDuration < TimeSpan.Zero || introspection.CacheDuration > C.BearerIssuerIntrospection.MaximumCacheDuration)
        {
            failures.Add($"{issuerAt}:{nameof(C.BearerIssuerIntrospection.CacheDuration)} must be between zero and {C.BearerIssuerIntrospection.MaximumCacheDuration}, which bounds how long a revoked token can still be accepted.");
        }

        if (introspection.Timeout < C.BearerIssuerIntrospection.MinimumTimeout || introspection.Timeout > C.BearerIssuerIntrospection.MaximumTimeout)
        {
            failures.Add($"{issuerAt}:{nameof(C.BearerIssuerIntrospection.Timeout)} must be between {C.BearerIssuerIntrospection.MinimumTimeout} and {C.BearerIssuerIntrospection.MaximumTimeout}.");
        }
    }

    static void ValidateResourceMetadata(RouteLocation location, C.BearerRoute route, ValidationState state)
    {
        var at = location.At;
        var serviceName = location.ServiceName;
        var metadataPaths = state.MetadataPaths;
        var failures = state.Failures;
        if (string.IsNullOrWhiteSpace(route.ResourceMetadataUrl))
        {
            return;
        }

        if (!BearerRouteTable.TryParseAuthorityUri(route.ResourceMetadataUrl, out var metadataUrl, out _)
            || AnonymousPathPolicy.Evaluate(metadataUrl.AbsolutePath, out var metadataPath) != AnonymousPathRejection.None)
        {
            failures.Add(
                $"{at}:{nameof(C.BearerRoute.ResourceMetadataUrl)} '{route.ResourceMetadataUrl}' must be an absolute HTTPS URL without query, " +
                "fragment or user information, whose path AuthProxy may forward to the service.");
            return;
        }

        if (metadataPaths.TryGetValue(metadataPath, out var owner) && !string.Equals(owner, serviceName, StringComparison.OrdinalIgnoreCase))
        {
            failures.Add($"{at}:{nameof(C.BearerRoute.ResourceMetadataUrl)} path '{metadataPath}' is already served by service '{owner}'.");
            return;
        }

        metadataPaths[metadataPath] = serviceName;
    }

    static bool Overlaps(string first, string second) =>
        new PathString(first).StartsWithSegments(second) || new PathString(second).StartsWithSegments(first);

    sealed record RouteLocation(string At, string ServiceName);

    sealed record ValidationState(
        Dictionary<string, string> Prefixes,
        Dictionary<string, string> MetadataPaths,
        string[] AnonymousPaths,
        List<string> Failures);
}
