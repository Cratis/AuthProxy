// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Primitives;
using Yarp.ReverseProxy.Model;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.ReverseProxy;

/// <summary>
/// States how a request is matched to a service, once, for both the route table and every component that has to
/// know which service a request targets.
/// </summary>
/// <remarks>
/// After endpoint selection, <see cref="Resolve"/> uses the selected proxy cluster. Without a proxy endpoint,
/// it follows the declared route order:
/// <list type="number">
///   <item>Anonymous paths (<see cref="C.Service.AnonymousPaths"/>), which do not require service authentication and are resolved only from a selected proxy endpoint.</item>
///   <item>Host and path prefix together (<see cref="C.Service.Hosts"/> and <see cref="C.Service.PathPrefix"/>).</item>
///   <item>Path prefix alone.</item>
///   <item>The <c language="text">Service-ID</c> header, then the <c language="text">service</c> query parameter.</item>
///   <item>Host alone.</item>
///   <item>The single configured service, when it declares neither hosts nor a path prefix.</item>
/// </list>
/// A path prefix claims its part of the URL, so it comes before an explicit selection; a host is a default an
/// explicit selection can override. Startup validation refuses configurations where two services could claim the
/// same request at the same step, so each step yields at most one service.
/// </remarks>
public static class ServiceRoutes
{
    /// <summary>
    /// The path prefix served by a service's backend rather than its frontend.
    /// </summary>
    public const string ApiPathPrefix = "/api";

    /// <summary>
    /// The query-string parameter naming the target service.
    /// </summary>
    public const string ServiceQueryParameter = "service";

    /// <summary>
    /// The route metadata key carrying the path prefix to remove from the forwarded path.
    /// </summary>
    public const string StripPathPrefixMetadataKey = "Cratis.AuthProxy.StripPathPrefix";

    /// <summary>
    /// Gets the normalized path prefix of a service, when it declares a usable one.
    /// </summary>
    /// <param name="service">The service.</param>
    /// <returns>The normalized prefix, or <see langword="null"/> when none is declared or it is unusable.</returns>
    public static string? PathPrefixOf(C.Service service) =>
        !string.IsNullOrWhiteSpace(service.PathPrefix)
        && AnonymousPaths.TryNormalize(service.PathPrefix, out var prefix)
        && !IsUnderApi(prefix)
            ? prefix
            : null;

    /// <summary>
    /// Gets the usable host entries of a service.
    /// </summary>
    /// <param name="service">The service.</param>
    /// <returns>The normalized host entries.</returns>
    public static IEnumerable<HostString> HostsOf(C.Service service) =>
        service.Hosts
            .Select(_ => TryParseHost(_, out var host) ? host : (HostString?)null)
            .OfType<HostString>();

    /// <summary>
    /// Parses a declared host entry.
    /// </summary>
    /// <param name="candidate">The declared entry.</param>
    /// <param name="host">The normalized host, lower-cased, with its port when one is declared.</param>
    /// <returns><see langword="true"/> when the entry is a host name with an optional port; otherwise <see langword="false"/>.</returns>
    public static bool TryParseHost(string? candidate, out HostString host)
    {
        host = default;
        var trimmed = candidate?.Trim() ?? string.Empty;
        if (trimmed.Length == 0 || trimmed.IndexOfAny(['/', '*', '?', '#', '@', ' ', '[', ']']) >= 0
            || trimmed.Count(_ => _ == ':') > 1)
        {
            return false;
        }

        var parsed = new HostString(trimmed.ToLowerInvariant());
        if (Uri.CheckHostName(parsed.Host.Trim('[', ']')) == UriHostNameType.Unknown
            || parsed.Port is <= 0 or > 65535
            || (parsed.Port is null && trimmed.Contains(':')))
        {
            return false;
        }

        host = parsed;
        return true;
    }

    /// <summary>
    /// Gets whether a declared host matches the host of a request, the way ASP.NET host matching does: an entry
    /// without a port matches every port, and a request without a port is on its scheme's default port.
    /// </summary>
    /// <param name="declared">The declared host.</param>
    /// <param name="request">The request.</param>
    /// <returns><see langword="true"/> when the request is for the declared host.</returns>
    public static bool Matches(HostString declared, HttpRequest request)
    {
        if (!string.Equals(declared.Host, request.Host.Host, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (declared.Port is null)
        {
            return true;
        }

        var port = request.Host.Port ?? (request.IsHttps ? 443 : 80);
        return port == declared.Port;
    }

    /// <summary>
    /// Gets whether two declared hosts can match the same request.
    /// </summary>
    /// <param name="first">The first host.</param>
    /// <param name="second">The second host.</param>
    /// <returns><see langword="true"/> when some request matches both.</returns>
    public static bool Overlap(HostString first, HostString second) =>
        string.Equals(first.Host, second.Host, StringComparison.OrdinalIgnoreCase)
        && (first.Port is null || second.Port is null || first.Port == second.Port);

    /// <summary>
    /// Gets whether two path prefixes can match the same request path.
    /// </summary>
    /// <param name="first">The first normalized prefix.</param>
    /// <param name="second">The second normalized prefix.</param>
    /// <returns><see langword="true"/> when one prefix equals the other or lies below it.</returns>
    public static bool Overlap(string first, string second) =>
        new PathString(first).StartsWithSegments(second, StringComparison.OrdinalIgnoreCase)
        || new PathString(second).StartsWithSegments(first, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Gets whether a service is reached through the plain catch-all routes of a single-service deployment.
    /// </summary>
    /// <param name="config">The configuration.</param>
    /// <returns><see langword="true"/> when there is exactly one service and it declares neither hosts nor a path prefix.</returns>
    public static bool UsesSingleServiceDefaults(C.AuthProxy config) =>
        config.Services.Count == 1
        && config.Services.Values.First() is var service
        && service.Hosts.Count == 0
        && string.IsNullOrWhiteSpace(service.PathPrefix);

    /// <summary>
    /// Resolves the selected proxy route's service, falling back to routing declarations without a proxy endpoint.
    /// </summary>
    /// <param name="request">The request.</param>
    /// <param name="config">The configuration.</param>
    /// <returns>The targeted service, or <see langword="null"/> when the request matches no service route.</returns>
    public static RoutedService? Resolve(HttpRequest request, C.AuthProxy config)
    {
        // Endpoint routing has already applied YARP's header parsing and route precedence. Its selected
        // cluster is authoritative: independently comparing raw headers can authorize a different service.
        if (request.HttpContext.GetEndpoint()?.Metadata.GetMetadata<RouteModel>() is { } route)
        {
            return config.Services
                .Where(_ => string.Equals(route.Config.ClusterId, $"{_.Key}-backend-cluster", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(route.Config.ClusterId, $"{_.Key}-frontend-cluster", StringComparison.OrdinalIgnoreCase))
                .Select(_ => new RoutedService(_.Key, _.Value))
                .FirstOrDefault();
        }

        if (config.Services.Count == 1)
        {
            // Every route in a single-service table leads to that service.
            var (name, service) = config.Services.First();
            return new(name, service);
        }

        var services = config.Services
            .Where(_ => _.Value.Backend is not null || _.Value.Frontend is not null)
            .Select(_ => new RoutedService(_.Key, _.Value))
            .ToArray();
        var path = request.Path;

        return ByPathPrefix(services, path, _ => HostsOf(_).Any(host => Matches(host, request)))
            ?? ByPathPrefix(services, path, _ => _.Hosts.Count == 0)
            ?? ByName(services, path, request.Headers[Headers.ServiceId], request.Query[ServiceQueryParameter])
            ?? services.FirstOrDefault(_ => PathPrefixOf(_.Service) is null && HostsOf(_.Service).Any(host => Matches(host, request)));
    }

    static RoutedService? ByPathPrefix(IEnumerable<RoutedService> services, PathString path, Func<C.Service, bool> hostMatches) =>
        services
            .Select(_ => (Routed: _, Prefix: PathPrefixOf(_.Service)))
            .Where(_ => _.Prefix is not null && hostMatches(_.Routed.Service) && path.StartsWithSegments(_.Prefix, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(_ => _.Prefix!.Length)
            .Select(_ => _.Routed)
            .FirstOrDefault();

    static RoutedService? ByName(RoutedService[] services, PathString path, StringValues header, StringValues query)
    {
        RoutedService? Named(StringValues values, Func<C.Service, bool> serves) =>
            services.FirstOrDefault(_ => serves(_.Service) && values.Any(value => string.Equals(value, _.Name, StringComparison.OrdinalIgnoreCase)));

        // The backend routes only take /api, and come first; the frontend routes take every path.
        if (path.StartsWithSegments(ApiPathPrefix, StringComparison.OrdinalIgnoreCase))
        {
            var backend = Named(header, _ => _.Backend is not null) ?? Named(query, _ => _.Backend is not null);
            if (backend is not null)
            {
                return backend;
            }
        }

        return Named(header, _ => _.Frontend is not null) ?? Named(query, _ => _.Frontend is not null);
    }

    static bool IsUnderApi(string prefix) => new PathString(prefix).StartsWithSegments(ApiPathPrefix, StringComparison.OrdinalIgnoreCase);
}
