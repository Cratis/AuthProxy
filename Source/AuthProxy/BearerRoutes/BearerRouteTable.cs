// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Runtime.CompilerServices;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.BearerRoutes;

/// <summary>
/// Resolves the bearer routes declared in <see cref="C.Service.BearerRoutes"/>.
/// </summary>
/// <remarks>
/// The bearer gate and the configuration validator have to agree on which paths are bearer routes and which
/// issuers they accept, so both resolve through here. A route that cannot be resolved — an unusable prefix or
/// metadata URL, an issuer that is not an absolute HTTPS URI, a service without a backend — is left out, which
/// leaves its path on the browser-session model; <see cref="BearerRouteConfigurationValidator"/> refuses such a
/// configuration at startup.
/// </remarks>
public static class BearerRouteTable
{
    /// <summary>
    /// The path segment RFC 8414 inserts between an issuer's host and path to locate its metadata document.
    /// </summary>
    public const string AuthorizationServerMetadataPath = "/.well-known/oauth-authorization-server";

    static readonly ConditionalWeakTable<C.AuthProxy, Resolution> _resolved = [];

    /// <summary>
    /// Gets every resolvable bearer route in the configuration.
    /// </summary>
    /// <param name="config">The auth proxy configuration to read.</param>
    /// <returns>The resolved routes.</returns>
    public static IReadOnlyList<ResolvedBearerRoute> All(C.AuthProxy config) => Resolve(config).Routes;

    /// <summary>
    /// Gets the resolvable bearer routes a single service declares.
    /// </summary>
    /// <param name="serviceName">The name of the service.</param>
    /// <param name="service">The service configuration.</param>
    /// <returns>The resolved routes.</returns>
    public static IEnumerable<ResolvedBearerRoute> For(string serviceName, C.Service service)
    {
        if (service.Backend is null)
        {
            yield break;
        }

        foreach (var route in service.BearerRoutes)
        {
            if (TryResolve(serviceName, service.Backend.BaseUrl, route, out var resolved))
            {
                yield return resolved;
            }
        }
    }

    /// <summary>
    /// Finds the bearer route covering a request path.
    /// </summary>
    /// <param name="path">The request path.</param>
    /// <param name="config">The auth proxy configuration to read.</param>
    /// <param name="route">The matching route.</param>
    /// <returns><see langword="true"/> when the path is on a bearer route; otherwise <see langword="false"/>.</returns>
    public static bool TryMatch(PathString path, C.AuthProxy config, out ResolvedBearerRoute route)
    {
        var routes = Resolve(config).Routes;
        for (var i = 0; i < routes.Length; i++)
        {
            if (path.StartsWithSegments(routes[i].Prefix))
            {
                route = routes[i];
                return true;
            }
        }

        route = default!;
        return false;
    }

    /// <summary>
    /// Determines whether a request path means the same thing to AuthProxy and to any backend that reads it.
    /// </summary>
    /// <param name="path">The request path, as decoded by the server.</param>
    /// <returns><see langword="true"/> when the path carries nothing a backend could decode or normalize differently; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// The server decodes a path before the gate sees it, except for an encoded <c language="text">/</c>, and a double-encoded
    /// character arrives still encoded. Either leaves a <c language="text">%</c> in the path, as does anything else the
    /// backend might decode once more. A backslash is a separator to some servers, and a dot segment is removed by
    /// most. A backend that decoded <c language="text">/mcp/..%2Fapi</c> into <c language="text">/api</c> would receive a principal
    /// vouched for on a bearer route at a path that is not one, so a bearer route accepts none of these.
    /// </remarks>
    public static bool IsUnambiguous(PathString path)
    {
        var value = path.Value ?? string.Empty;
        if (value.Contains('%', StringComparison.Ordinal) || value.Contains('\\', StringComparison.Ordinal))
        {
            return false;
        }

        foreach (var segment in value.Split('/'))
        {
            if (string.Equals(segment, ".", StringComparison.Ordinal) || string.Equals(segment, "..", StringComparison.Ordinal))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Finds the bearer route whose protected-resource metadata document a request path names.
    /// </summary>
    /// <param name="path">The request path.</param>
    /// <param name="config">The auth proxy configuration to read.</param>
    /// <param name="route">The route declaring that metadata path.</param>
    /// <returns><see langword="true"/> when the path is exactly a declared metadata path; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// Matched exactly, not as a prefix: the metadata document is the one thing on a bearer route that is served
    /// without a token, so nothing under it is.
    /// </remarks>
    public static bool TryMatchResourceMetadata(PathString path, C.AuthProxy config, out ResolvedBearerRoute route)
    {
        var candidate = (path.Value ?? string.Empty).TrimEnd('/');
        var routes = Resolve(config).Routes;
        for (var i = 0; i < routes.Length; i++)
        {
            if (routes[i].ResourceMetadataPath is { } metadataPath
                && string.Equals(metadataPath, candidate, StringComparison.OrdinalIgnoreCase))
            {
                route = routes[i];
                return true;
            }
        }

        route = default!;
        return false;
    }

    /// <summary>
    /// Determines whether an issuer is accepted on any bearer route.
    /// </summary>
    /// <param name="issuer">The issuer identifier to look for.</param>
    /// <param name="config">The auth proxy configuration to read.</param>
    /// <returns><see langword="true"/> when some bearer route accepts the issuer; otherwise <see langword="false"/>.</returns>
    public static bool IsBearerRouteIssuer(string issuer, C.AuthProxy config) => Resolve(config).Issuers.Contains(issuer);

    /// <summary>
    /// Resolves a configured issuer, applying its defaults.
    /// </summary>
    /// <param name="issuer">The configured issuer.</param>
    /// <param name="resolved">The resolved issuer.</param>
    /// <returns><see langword="true"/> when the issuer is usable; otherwise <see langword="false"/>.</returns>
    public static bool TryResolveIssuer(C.BearerIssuer issuer, out ResolvedBearerIssuer resolved)
    {
        resolved = default!;

        if (!TryParseAuthorityUri(issuer.Issuer, out var issuerUri, out var isLoopbackHttp))
        {
            return false;
        }

        string metadataAddress;
        if (string.IsNullOrWhiteSpace(issuer.MetadataAddress))
        {
            metadataAddress = $"{issuerUri.GetLeftPart(UriPartial.Authority)}{AuthorizationServerMetadataPath}{issuerUri.AbsolutePath.TrimEnd('/')}";
        }
        else if (TryParseAuthorityUri(issuer.MetadataAddress, out var metadataUri, out var metadataIsLoopbackHttp)
            && (!metadataIsLoopbackHttp || isLoopbackHttp))
        {
            metadataAddress = metadataUri.AbsoluteUri;
        }
        else
        {
            return false;
        }

        var tokenTypes = issuer.TokenTypes.Where(_ => !string.IsNullOrWhiteSpace(_)).Select(_ => _.Trim()).ToArray();
        resolved = new ResolvedBearerIssuer(
            issuer.Issuer,
            metadataAddress,
            tokenTypes.Length > 0 ? tokenTypes : C.BearerIssuer.DefaultTokenTypes,
            RequireHttps: !isLoopbackHttp);

        return true;
    }

    /// <summary>
    /// Parses an absolute URI an authorization server or a resource is identified by.
    /// </summary>
    /// <param name="candidate">The configured value.</param>
    /// <param name="uri">The parsed URI.</param>
    /// <param name="isLoopbackHttp">Whether the URI is a plain-HTTP loopback development address.</param>
    /// <returns><see langword="true"/> when the value is usable; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// HTTPS is required, except on a loopback host, so neither a token's trust anchor nor the address a client is
    /// told to fetch metadata from can be downgraded outside a developer's own machine. Query, fragment and user
    /// information are refused because none of them belongs in an identifier.
    /// </remarks>
    public static bool TryParseAuthorityUri(string? candidate, out Uri uri, out bool isLoopbackHttp)
    {
        isLoopbackHttp = false;
        if (string.IsNullOrWhiteSpace(candidate)
            || !Uri.TryCreate(candidate.Trim(), UriKind.Absolute, out uri!)
            || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment)
            || !string.IsNullOrEmpty(uri.UserInfo))
        {
            uri = default!;
            return false;
        }

        if (string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal))
        {
            return true;
        }

        if (string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal) && uri.IsLoopback)
        {
            isLoopbackHttp = true;
            return true;
        }

        uri = default!;
        return false;
    }

    static bool TryResolve(string serviceName, string backendBaseUrl, C.BearerRoute route, out ResolvedBearerRoute resolved)
    {
        resolved = default!;

        if (AnonymousPathPolicy.Evaluate(route.PathPrefix, out var prefix) != AnonymousPathRejection.None
            || route.Issuers.Count == 0
            || route.Audiences.All(string.IsNullOrWhiteSpace))
        {
            return false;
        }

        var issuers = new List<ResolvedBearerIssuer>();
        foreach (var issuer in route.Issuers)
        {
            if (!TryResolveIssuer(issuer, out var resolvedIssuer))
            {
                return false;
            }

            issuers.Add(resolvedIssuer);
        }

        Uri? metadataUrl = null;
        string? metadataPath = null;
        if (!string.IsNullOrWhiteSpace(route.ResourceMetadataUrl))
        {
            if (!TryParseAuthorityUri(route.ResourceMetadataUrl, out metadataUrl, out _)
                || AnonymousPathPolicy.Evaluate(metadataUrl.AbsolutePath, out var normalizedMetadataPath) != AnonymousPathRejection.None)
            {
                return false;
            }

            metadataPath = normalizedMetadataPath;
        }

        resolved = new ResolvedBearerRoute(serviceName, backendBaseUrl, prefix, issuers, route, metadataUrl, metadataPath);
        return true;
    }

    static Resolution Resolve(C.AuthProxy config) => _resolved.GetValue(config, Create);

    static Resolution Create(C.AuthProxy config)
    {
        // Longest prefix first, so a narrower route declared under a wider one is the one that applies to it.
        var routes = config.Services
            .SelectMany(_ => For(_.Key, _.Value))
            .OrderByDescending(_ => _.Prefix.Length)
            .ToArray();
        var issuers = routes
            .SelectMany(_ => _.Issuers)
            .Select(_ => _.Issuer)
            .ToHashSet(StringComparer.Ordinal);

        return new Resolution(routes, issuers);
    }

    sealed record Resolution(ResolvedBearerRoute[] Routes, HashSet<string> Issuers);
}
