// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Buffers;
using Cratis.AuthProxy.Authentication;
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
        var failures = new List<string>();
        var prefixes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var metadataPaths = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var anonymousPaths = options.Services.Values.SelectMany(AnonymousPaths.For).ToArray();

        foreach (var (serviceName, service) in options.Services)
        {
            for (var index = 0; index < service.BearerRoutes.Count; index++)
            {
                var route = service.BearerRoutes[index];
                var at = $"{C.AuthProxy.SectionKey}:{nameof(C.AuthProxy.Services)}:{serviceName}:{nameof(C.Service.BearerRoutes)}:{index}";
                ValidateRoute(at, serviceName, service, route, prefixes, metadataPaths, anonymousPaths, failures);

                if (options.RequiresIdentityVerification && !route.AcceptWithoutIdentityVerification)
                {
                    failures.Add(
                        $"{at}: the deployment requires identity verification ({nameof(C.IdentityVerificationMode)}.{nameof(C.IdentityVerificationMode.Required)}), " +
                        "which a bearer route does not perform: it has no browser session to verify through /.cratis/me. Set " +
                        $"{nameof(C.BearerRoute.AcceptWithoutIdentityVerification)} on the route to accept its callers on the token and " +
                        "the claim requirements alone, or remove the route.");
                }
            }
        }

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    static void ValidateRoute(
        string at,
        string serviceName,
        C.Service service,
        C.BearerRoute route,
        Dictionary<string, string> prefixes,
        Dictionary<string, string> metadataPaths,
        string[] anonymousPaths,
        List<string> failures)
    {
        if (service.Backend is null || string.IsNullOrWhiteSpace(service.Backend.BaseUrl))
        {
            failures.Add($"{at}: the service declares no backend, so a bearer route has nothing to forward to.");
        }

        var rejection = AnonymousPathPolicy.Evaluate(route.PathPrefix, out var prefix);
        if (rejection != AnonymousPathRejection.None)
        {
            failures.Add($"{at}:{nameof(C.BearerRoute.PathPrefix)} '{route.PathPrefix}' is not usable ({rejection}).");
        }
        else
        {
            if (!prefixes.TryAdd(prefix, serviceName))
            {
                failures.Add($"{at}:{nameof(C.BearerRoute.PathPrefix)} '{prefix}' is already a bearer route of service '{prefixes[prefix]}'.");
            }

            var overlapping = anonymousPaths.FirstOrDefault(_ => Overlaps(_, prefix));
            if (overlapping is not null)
            {
                failures.Add($"{at}:{nameof(C.BearerRoute.PathPrefix)} '{prefix}' overlaps the anonymous path '{overlapping}'. A path cannot be both.");
            }
        }

        if (route.Issuers.Count == 0)
        {
            failures.Add($"{at}:{nameof(C.BearerRoute.Issuers)} is empty. A bearer route must name the authorization server whose tokens it accepts.");
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

        if (route.Audiences.All(string.IsNullOrWhiteSpace))
        {
            failures.Add($"{at}:{nameof(C.BearerRoute.Audiences)} is empty. A bearer route must name the audience its tokens are issued for.");
        }

        foreach (var scope in route.RequiredScopes.Where(_ => !string.IsNullOrWhiteSpace(_)).Select(_ => _.Trim()))
        {
            if (scope.AsSpan().IndexOfAnyExcept(_scopeCharacters) >= 0)
            {
                failures.Add($"{at}:{nameof(C.BearerRoute.RequiredScopes)} '{scope}' is not a valid OAuth scope.");
            }
        }

        ValidateResourceMetadata(at, serviceName, route, metadataPaths, failures);

        if (route.ClockSkew is { } skew && (skew < TimeSpan.Zero || skew > C.BearerRoute.MaximumClockSkew))
        {
            failures.Add($"{at}:{nameof(C.BearerRoute.ClockSkew)} must be between zero and {C.BearerRoute.MaximumClockSkew}.");
        }

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

        var mappingTargets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var tenantClaim = string.IsNullOrWhiteSpace(route.TenantClaimType) ? C.BearerRoute.DefaultTenantClaimType : route.TenantClaimType.Trim();
        foreach (var (target, source) in route.ClaimMappings)
        {
            if (string.IsNullOrWhiteSpace(target) || string.IsNullOrWhiteSpace(source))
            {
                failures.Add($"{at}:{nameof(C.BearerRoute.ClaimMappings)} has a mapping with an empty claim type.");
            }
            else if (CanonicalIdentityClaims.IsReserved(target) || BearerRouteClaims.IsReserved(target) || RoleClaims.Is(target))
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

    static void ValidateResourceMetadata(
        string at,
        string serviceName,
        C.BearerRoute route,
        Dictionary<string, string> metadataPaths,
        List<string> failures)
    {
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
}
