// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Yarp.ReverseProxy.Configuration;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.ReverseProxy;

/// <summary>
/// Builds and serves the YARP <see cref="IProxyConfig"/> dynamically from the
/// <see cref="C.AuthProxy.Services"/> configuration section.
///
/// <para>
/// Each microservice generates routes that are matched by:
/// <list type="bullet">
///   <item>its declared <see cref="C.Service.PathPrefix"/>, optionally on its declared <see cref="C.Service.Hosts"/>,</item>
///   <item>a <c language="text">Service-ID</c> HTTP header set to the microservice name,</item>
///   <item>a <c language="text">service</c> query-string parameter set to the microservice name, or</item>
///   <item>its declared <see cref="C.Service.Hosts"/>.</item>
/// </list>
/// The precedence between them is stated once, in <see cref="ServiceRoutes"/>, and is expressed here as route order.
/// </para>
/// <para>
/// When only a <b>single</b> microservice is configured, and it declares neither hosts nor a path prefix, the
/// header / query parameter is optional and a plain catch-all route is also registered so that the single
/// microservice works without any special client configuration.
/// </para>
/// <para>
/// The table is rebuilt whenever the configuration reloads, so it keeps agreeing with the middlewares that
/// read the same configuration per request — see <see cref="Rebuild"/>.
/// </para>
/// </summary>
public class MicroserviceReverseProxyConfigProvider : IProxyConfigProvider, IDisposable
{
    /// <summary>
    /// The YARP well-known authorization policy name that disables authorization for a route. Shared with
    /// <see cref="Identity.IdentityForwardingGuardMiddleware"/>, which exempts routes carrying it from the
    /// forwardable-identity requirement.
    /// </summary>
    internal const string AnonymousAuthorizationPolicy = "anonymous";

    /// <summary>
    /// The cluster metadata key naming the service a cluster belongs to.
    /// </summary>
    internal const string ServiceMetadataKey = "Cratis.AuthProxy.Service";

    /// <summary>
    /// The cluster metadata key naming which endpoint of the service a cluster is.
    /// </summary>
    internal const string EndpointMetadataKey = "Cratis.AuthProxy.Endpoint";

    /// <summary>
    /// The cluster metadata key holding the access token policy selected with its destination.
    /// </summary>
    internal const string AccessTokenMetadataKey = "Cratis.AuthProxy.AccessToken";

    /// <summary>
    /// The cluster metadata key binding the access token policy to its versioned destination.
    /// </summary>
    internal const string DestinationMetadataKey = "Cratis.AuthProxy.Destination";

    /// <summary>
    /// The <see cref="EndpointMetadataKey"/> value of a service's backend cluster.
    /// </summary>
    internal const string BackendEndpoint = "Backend";

    /// <summary>
    /// The <see cref="EndpointMetadataKey"/> value of a service's frontend cluster.
    /// </summary>
    internal const string FrontendEndpoint = "Frontend";

    /// <summary>
    /// The path prefix served by a service's backend rather than its frontend.
    /// </summary>
    const string ApiPathPrefix = ServiceRoutes.ApiPathPrefix;

    /// <summary>
    /// The route order of a host-and-prefix backend route. Route orders run lowest first, anonymous paths are 0,
    /// and <see cref="ServiceRoutes"/> explains why the steps that follow are in this order.
    /// </summary>
    const int HostAndPrefixApiOrder = 1;
    const int HostAndPrefixOrder = 2;
    const int PrefixApiOrder = 3;
    const int PrefixOrder = 4;
    const int HeaderApiOrder = 10;
    const int QueryApiOrder = 11;
    const int HeaderOrder = 20;
    const int QueryOrder = 21;
    const int HostApiOrder = 30;
    const int HostOrder = 31;

    readonly InMemoryConfigProvider _inner;
    readonly ILogger<MicroserviceReverseProxyConfigProvider> _logger;
    readonly Lock _rebuilding = new();
    IDisposable? _configurationChanged;

    /// <summary>
    /// Initializes a new instance of the <see cref="MicroserviceReverseProxyConfigProvider"/> class.
    /// </summary>
    /// <param name="config">The options monitor providing the current auth proxy configuration.</param>
    /// <param name="logger">The logger.</param>
    public MicroserviceReverseProxyConfigProvider(
        IOptionsMonitor<C.AuthProxy> config,
        ILogger<MicroserviceReverseProxyConfigProvider> logger)
    {
        _logger = logger;
        var snapshot = config.CurrentValue;
        _inner = new InMemoryConfigProvider(
            BuildRoutes(snapshot, logger),
            BuildClusters(snapshot));
        _configurationChanged = config.OnChange(Rebuild);
    }

    /// <inheritdoc/>
    public IProxyConfig GetConfig() => _inner.GetConfig();

    /// <inheritdoc/>
    public void Dispose()
    {
        // Idempotent: this instance is registered both as itself and as IProxyConfigProvider, so the
        // container can hand the same object to two disposal registrations.
        _configurationChanged?.Dispose();
        _configurationChanged = null;
        GC.SuppressFinalize(this);
    }

    static List<RouteConfig> BuildRoutes(C.AuthProxy config, ILogger logger)
    {
        var routes = new List<RouteConfig>();
        var services = config.Services;
        var isSingleMicroservice = ServiceRoutes.UsesSingleServiceDefaults(config);

        // A declared prefix is matched without any service-selection header or query parameter, so two
        // services declaring the same prefix would emit two routes with an identical template and an
        // identical order — which ASP.NET cannot choose between, and reports as AmbiguousMatchException on
        // the declared path. Claiming each prefix for the first service that can actually serve it keeps
        // the path anonymous, which is what every declaring service asked for, and the table unambiguous.
        var claimedAnonymousPaths = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var (name, ms) in services)
        {
            var key = name.ToLowerInvariant();

            ReportRefusedAnonymousPaths(key, ms, logger);
            routes.AddRange(AnonymousRoutes(name, ms, claimedAnonymousPaths, logger));
            routes.AddRange(PathPrefixRoutes(name, ms));
            routes.AddRange(HostRoutes(name, ms));

            if (ms.Backend is not null)
            {
                routes.AddRange(BackendRoutes(name, isSingleMicroservice));
            }

            if (ms.Frontend is not null)
            {
                routes.AddRange(FrontendRoutes(name));
            }
        }

        // In a single-microservice deployment also add a plain catch-all so the
        // frontend is reachable without any routing header or query parameter. A single service that declares
        // hosts or a path prefix asked to be reached only through them, so it gets no catch-all.
        if (isSingleMicroservice)
        {
            var (name, ms) = services.First();
            var key = name.ToLowerInvariant();

            if (ms.Frontend is not null)
            {
                routes.Add(new RouteConfig
                {
                    RouteId = $"{key}-frontend-catchall-default",
                    Metadata = ServiceMetadata(name),
                    ClusterId = FrontendClusterId(key),
                    AuthorizationPolicy = "default",
                    Match = new RouteMatch { Path = "/{**catch-all}" },
                    Order = 100,
                });
            }
            else if (ms.Backend is not null)
            {
                routes.Add(new RouteConfig
                {
                    RouteId = $"{key}-backend-catchall-default",
                    Metadata = ServiceMetadata(name),
                    ClusterId = BackendClusterId(key),
                    AuthorizationPolicy = "default",
                    Match = new RouteMatch { Path = "/{**catch-all}" },
                    Order = 100,
                });
            }
        }

        return routes;
    }

    /// <summary>
    /// Reports every declared anonymous path that was refused, and why.
    /// </summary>
    /// <param name="microserviceKey">The lower-cased service key.</param>
    /// <param name="service">The service configuration.</param>
    /// <param name="logger">The logger, used to name each refused entry.</param>
    /// <remarks>
    /// A refusal is fail-closed, so nothing breaks loudly — the path keeps demanding a login. That is the
    /// safe outcome and an invisible one: an operator who mistypes a prefix, or pastes one carrying an
    /// encoded character, gets a service that behaves exactly as if they had never declared it. Startup is
    /// the only place the two can be compared, so the refusal is named here.
    /// </remarks>
    static void ReportRefusedAnonymousPaths(string microserviceKey, C.Service service, ILogger logger)
    {
        foreach (var refused in AnonymousPaths.Evaluate(service).Where(_ => !_.IsUsable))
        {
            logger.AnonymousPathRefused(refused.DeclaredForDisplay, microserviceKey, refused.Rejection);
        }
    }

    /// <summary>
    /// Builds the routes for the paths a service declares in <see cref="C.Service.AnonymousPaths"/>.
    /// </summary>
    /// <param name="serviceName">The configured service name.</param>
    /// <param name="service">The service configuration.</param>
    /// <param name="claimedPaths">The prefixes already claimed, keyed by the service serving each; claimed here as they are emitted.</param>
    /// <param name="logger">The logger, used to name a prefix an earlier service already claimed.</param>
    /// <returns>One route per declared anonymous path prefix not already claimed.</returns>
    /// <remarks>
    /// These are the only routes not generated with <c language="text">AuthorizationPolicy = "default"</c>. That default is
    /// <c language="text">RequireAuthenticatedUser()</c>, so without this a declared anonymous path clears
    /// <c language="text">SelectProviderMiddleware</c> only to be stopped one step later — refused by authorization on the
    /// catch-all route in a single-service deployment, or matching no route at all in a multi-service one,
    /// where every other route is selected by a header or query parameter an anonymous caller has no reason
    /// to send. The same closed door either way. None of the built-in skip-list paths (invite,
    /// registration, authentication UI, <c language="text">/_pages</c>) is ever proxied to a service, so this is the first
    /// case where an unauthenticated request is meant to reach a backend, and the first that needs the
    /// policy relaxed.
    /// <para>
    /// The relaxation is scoped to exactly the declared prefixes and nothing else: with no
    /// <c language="text">AnonymousPaths</c> declared this yields no routes and the table is what it was before. Each
    /// prefix is emitted as a catch-all so it covers the prefix itself and everything under it, which
    /// matches the segment-prefix semantics the middlewares apply because
    /// <see cref="AnonymousPaths.TryNormalize"/> only admits prefixes made of literal segments.
    /// </para>
    /// <para>
    /// Order 0 puts these ahead of the header- and query-selected routes, which is what relaxes the policy
    /// but also claims the prefix for the whole proxy: an anonymous caller cannot be expected to send a
    /// service-selection header, so the declared path is necessarily what identifies the service. In a
    /// multi-service deployment no other service can serve anything under a declared prefix.
    /// </para>
    /// </remarks>
    static IEnumerable<RouteConfig> AnonymousRoutes(
        string serviceName,
        C.Service service,
        Dictionary<string, string> claimedPaths,
        ILogger logger)
    {
        var microserviceKey = serviceName.ToLowerInvariant();
        var index = 0;

        foreach (var path in AnonymousPaths.For(service))
        {
            if (claimedPaths.TryGetValue(path, out var claimedBy))
            {
                // Silently routing this service's traffic to another service's backend is the kind of
                // thing an operator only discovers from the wrong response body, so it is named here.
                logger.AnonymousPathAlreadyClaimed(path, claimedBy, microserviceKey);
                continue;
            }

            // Mirror the authenticated split: /api goes to the backend, anything else to the frontend,
            // falling back to whichever endpoint the service actually declares.
            var prefix = ServiceRoutes.PathPrefixOf(service);
            var relativePath = new PathString(path);
            if (prefix is not null && relativePath.StartsWithSegments(prefix, StringComparison.OrdinalIgnoreCase, out var remaining))
            {
                relativePath = remaining;
            }

            var prefersBackend = relativePath.StartsWithSegments(ApiPathPrefix, StringComparison.OrdinalIgnoreCase);
            var clusterId = (prefersBackend, service.Backend, service.Frontend) switch
            {
                (true, not null, _) => BackendClusterId(microserviceKey),
                (false, _, not null) => FrontendClusterId(microserviceKey),
                (_, not null, null) => BackendClusterId(microserviceKey),
                (_, null, not null) => FrontendClusterId(microserviceKey),
                _ => null,
            };

            // A service entry does not have to declare an endpoint — the lobby's registration service is
            // configured that way — and one with nothing to forward to produces no route. Claiming only
            // when a route is actually emitted keeps such an entry from taking the prefix away from a
            // service that can serve it, which would leave the path matching no route at all while all
            // three middlewares went on treating it as anonymous.
            if (clusterId is null)
            {
                continue;
            }

            claimedPaths[path] = microserviceKey;

            // An anonymous path below a stripped prefix is forwarded the way the rest of the prefix is, so the
            // service sees one consistent path shape whether or not the caller has a session.
            var stripsPrefix = service.StripPathPrefix
                && prefix is not null
                && new PathString(path).StartsWithSegments(prefix, StringComparison.OrdinalIgnoreCase);

            yield return new RouteConfig
            {
                RouteId = $"{microserviceKey}-anonymous-{index}",
                ClusterId = clusterId,
                AuthorizationPolicy = AnonymousAuthorizationPolicy,
                Match = new RouteMatch { Path = $"{path}/{{**catch-all}}" },
                Order = 0,
                Metadata = ServiceMetadata(serviceName, stripsPrefix ? prefix : null),
            };

            index++;
        }
    }

    /// <summary>
    /// Builds the routes for a service's declared <see cref="C.Service.PathPrefix"/>.
    /// </summary>
    /// <param name="serviceName">The configured service name.</param>
    /// <param name="service">The service configuration.</param>
    /// <returns>The prefix routes: <c language="text">{prefix}/api</c> to the backend, the rest of the prefix to the frontend.</returns>
    /// <remarks>
    /// A prefix declared together with hosts only answers on those hosts, and is ordered ahead of a prefix that
    /// answers on every host, so a host-specific declaration wins where both apply.
    /// </remarks>
    static IEnumerable<RouteConfig> PathPrefixRoutes(string serviceName, C.Service service)
    {
        var microserviceKey = serviceName.ToLowerInvariant();
        if (ServiceRoutes.PathPrefixOf(service) is not { } prefix)
        {
            yield break;
        }

        var hosts = ServiceRoutes.HostsOf(service).Select(_ => _.Value!).ToArray();
        var onHosts = hosts.Length > 0;
        var metadata = ServiceMetadata(serviceName, service.StripPathPrefix ? prefix : null);

        if (service.Backend is not null)
        {
            yield return new RouteConfig
            {
                RouteId = $"{microserviceKey}-prefix-api",
                ClusterId = BackendClusterId(microserviceKey),
                AuthorizationPolicy = "default",
                Match = new RouteMatch { Path = $"{prefix}{ApiPathPrefix}/{{**catch-all}}", Hosts = onHosts ? hosts : null },
                Order = onHosts ? HostAndPrefixApiOrder : PrefixApiOrder,
                Metadata = metadata,
            };
        }

        if (CatchAllClusterId(microserviceKey, service) is { } clusterId)
        {
            yield return new RouteConfig
            {
                RouteId = $"{microserviceKey}-prefix",
                ClusterId = clusterId,
                AuthorizationPolicy = "default",
                Match = new RouteMatch { Path = $"{prefix}/{{**catch-all}}", Hosts = onHosts ? hosts : null },
                Order = onHosts ? HostAndPrefixOrder : PrefixOrder,
                Metadata = metadata,
            };
        }
    }

    /// <summary>
    /// Builds the routes for a service's declared <see cref="C.Service.Hosts"/>, when it declares no path prefix.
    /// </summary>
    /// <param name="serviceName">The configured service name.</param>
    /// <param name="service">The service configuration.</param>
    /// <returns>The host routes: <c language="text">/api</c> to the backend, everything else to the frontend.</returns>
    /// <remarks>
    /// Ordered behind the header- and query-selected routes: a host names the service a request goes to when the
    /// request does not say, and a frontend on that host can still name another service's backend.
    /// </remarks>
    static IEnumerable<RouteConfig> HostRoutes(string serviceName, C.Service service)
    {
        var microserviceKey = serviceName.ToLowerInvariant();
        var hosts = ServiceRoutes.HostsOf(service).Select(_ => _.Value!).ToArray();
        if (hosts.Length == 0 || ServiceRoutes.PathPrefixOf(service) is not null)
        {
            yield break;
        }

        if (service.Backend is not null)
        {
            yield return new RouteConfig
            {
                RouteId = $"{microserviceKey}-host-api",
                Metadata = ServiceMetadata(serviceName),
                ClusterId = BackendClusterId(microserviceKey),
                AuthorizationPolicy = "default",
                Match = new RouteMatch { Path = $"{ApiPathPrefix}/{{**catch-all}}", Hosts = hosts },
                Order = HostApiOrder,
            };
        }

        if (CatchAllClusterId(microserviceKey, service) is { } clusterId)
        {
            yield return new RouteConfig
            {
                RouteId = $"{microserviceKey}-host",
                Metadata = ServiceMetadata(serviceName),
                ClusterId = clusterId,
                AuthorizationPolicy = "default",
                Match = new RouteMatch { Path = "/{**catch-all}", Hosts = hosts },
                Order = HostOrder,
            };
        }
    }

    static string? CatchAllClusterId(string microserviceKey, C.Service service) => (service.Frontend, service.Backend) switch
    {
        (not null, _) => FrontendClusterId(microserviceKey),
        (null, not null) => BackendClusterId(microserviceKey),
        _ => null,
    };

    static IEnumerable<RouteConfig> BackendRoutes(string serviceName, bool isSingle)
    {
        var microserviceKey = serviceName.ToLowerInvariant();

        // Header-matched API route
        yield return new RouteConfig
        {
            RouteId = $"{microserviceKey}-backend-header-api",
            Metadata = ServiceMetadata(serviceName),
            ClusterId = BackendClusterId(microserviceKey),
            AuthorizationPolicy = "default",
            Match = new RouteMatch
            {
                Path = "/api/{**catch-all}",
                Headers =
                [
                    new RouteHeader
                    {
                        Name = Headers.ServiceId,
                        Mode = HeaderMatchMode.ExactHeader,
                        IsCaseSensitive = false,
                        Values = [microserviceKey],
                    }
                ],
            },
            Order = HeaderApiOrder,
        };

        // Query-parameter–matched API route (adds the header for downstream).
        // Ordered behind the header-matched route rather than beside it: a caller that sends both a
        // x-cratis-microservice header and a ?service= parameter satisfies both, and two candidates at the same order
        // with the same template are an AmbiguousMatchException. Endpoint selection runs ahead of
        // authentication, so that surfaces to an unauthenticated caller as a bare 500 — trivially
        // reachable, and in Development a stack trace. A distinct order makes the header win instead.
        yield return new RouteConfig
        {
            RouteId = $"{microserviceKey}-backend-query-api",
            Metadata = ServiceMetadata(serviceName),
            ClusterId = BackendClusterId(microserviceKey),
            AuthorizationPolicy = "default",
            Match = new RouteMatch
            {
                Path = "/api/{**catch-all}",
                QueryParameters =
                [
                    new RouteQueryParameter
                    {
                        Name = ServiceRoutes.ServiceQueryParameter,
                        Mode = QueryParameterMatchMode.Exact,
                        IsCaseSensitive = false,
                        Values = [microserviceKey],
                    }
                ],
            },
            Order = QueryApiOrder,
        };

        // Plain /api catch-all when there is only one microservice.
        if (isSingle)
        {
            yield return new RouteConfig
            {
                RouteId = $"{microserviceKey}-backend-api-default",
                Metadata = ServiceMetadata(serviceName),
                ClusterId = BackendClusterId(microserviceKey),
                AuthorizationPolicy = "default",
                Match = new RouteMatch { Path = "/api/{**catch-all}" },
                Order = 50,
            };
        }
    }

    static IEnumerable<RouteConfig> FrontendRoutes(string serviceName)
    {
        var microserviceKey = serviceName.ToLowerInvariant();

        // Header-matched frontend route
        yield return new RouteConfig
        {
            RouteId = $"{microserviceKey}-frontend-header",
            Metadata = ServiceMetadata(serviceName),
            ClusterId = FrontendClusterId(microserviceKey),
            AuthorizationPolicy = "default",
            Match = new RouteMatch
            {
                Path = "/{**catch-all}",
                Headers =
                [
                    new RouteHeader
                    {
                        Name = Headers.ServiceId,
                        Mode = HeaderMatchMode.ExactHeader,
                        IsCaseSensitive = false,
                        Values = [microserviceKey],
                    }
                ],
            },
            Order = HeaderOrder,
        };

        // Query-parameter–matched frontend route, ordered behind the header-matched one for the same
        // reason as the backend pair: satisfying both must select one route, not raise an ambiguity.
        yield return new RouteConfig
        {
            RouteId = $"{microserviceKey}-frontend-query",
            Metadata = ServiceMetadata(serviceName),
            ClusterId = FrontendClusterId(microserviceKey),
            AuthorizationPolicy = "default",
            Match = new RouteMatch
            {
                Path = "/{**catch-all}",
                QueryParameters =
                [
                    new RouteQueryParameter
                    {
                        Name = ServiceRoutes.ServiceQueryParameter,
                        Mode = QueryParameterMatchMode.Exact,
                        IsCaseSensitive = false,
                        Values = [microserviceKey],
                    }
                ],
            },
            Order = QueryOrder,
        };
    }

    static List<ClusterConfig> BuildClusters(C.AuthProxy config)
    {
        var clusters = new List<ClusterConfig>();
        foreach (var (name, ms) in config.Services)
        {
            var key = name.ToLowerInvariant();

            if (ms.Backend is not null)
            {
                var destinationId = BackendDestinationId(key, ms);
                var metadata = ClusterMetadata(key, BackendEndpoint, ms.AccessToken);
                metadata[DestinationMetadataKey] = destinationId;
                clusters.Add(ClusterFor(config, ms, ms.Backend) with
                {
                    ClusterId = BackendClusterId(key),

                    // Give a changed binding a new destination state so YARP cannot mutate the address while
                    // a request awaits a token. Metadata lets forwarding reject mixed snapshots during reload.
                    Destinations = new Dictionary<string, DestinationConfig>
                    {
                        [destinationId] = new() { Address = ms.Backend.BaseUrl }
                    },
                    Metadata = metadata,
                });
            }

            if (ms.Frontend is not null)
            {
                clusters.Add(ClusterFor(config, ms, ms.Frontend) with
                {
                    ClusterId = FrontendClusterId(key),
                    Destinations = new Dictionary<string, DestinationConfig>
                    {
                        ["destination1"] = new() { Address = ms.Frontend.BaseUrl }
                    },
                    Metadata = ClusterMetadata(key, FrontendEndpoint),
                });
            }
        }

        return clusters;
    }

    static Dictionary<string, string> ClusterMetadata(string key, string endpoint, C.ServiceAccessToken? accessToken = null)
    {
        var metadata = new Dictionary<string, string>
        {
            [ServiceMetadataKey] = key,
            [EndpointMetadataKey] = endpoint,
        };
        if (accessToken is not null)
        {
            metadata[AccessTokenMetadataKey] = JsonSerializer.Serialize(accessToken);
        }

        return metadata;
    }

    static string BackendDestinationId(string key, C.Service service)
    {
        if (service.AccessToken is null)
        {
            return "destination1";
        }

        var binding = JsonSerializer.Serialize(new { Address = service.Backend?.BaseUrl, Policy = service.AccessToken });
        var version = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(binding)));

        return $"{key}-backend-destination-{version}";
    }

    /// <summary>
    /// Creates the cluster skeleton for an endpoint, carrying the activity timeout that applies to it.
    /// </summary>
    /// <param name="config">The root configuration.</param>
    /// <param name="service">The service the endpoint belongs to.</param>
    /// <param name="endpoint">The endpoint.</param>
    /// <returns>A cluster with its request settings filled in.</returns>
    /// <remarks>
    /// The most specific statement wins: the endpoint's own, then its service's, then the root's, then
    /// <see cref="C.AuthProxy.DefaultActivityTimeout"/>. The same value governs plain requests, WebSocket
    /// sessions and Server-Sent Events streams, because YARP measures all of them as time since data last
    /// moved in either direction.
    /// </remarks>
    static ClusterConfig ClusterFor(C.AuthProxy config, C.Service service, C.ServiceEndpoint endpoint) => new()
    {
        HttpRequest = new()
        {
            ActivityTimeout = endpoint.ActivityTimeout
                ?? service.ActivityTimeout
                ?? config.ActivityTimeout
                ?? C.AuthProxy.DefaultActivityTimeout,
        },
    };

    static Dictionary<string, string> ServiceMetadata(string serviceName, string? stripPrefix = null)
    {
        var metadata = new Dictionary<string, string> { [ServiceSelection.RouteMetadataKey] = serviceName };
        if (stripPrefix is not null)
        {
            metadata[ServiceRoutes.StripPathPrefixMetadataKey] = stripPrefix;
        }

        return metadata;
    }

    static string BackendClusterId(string key) => $"{key}-backend-cluster";
    static string FrontendClusterId(string key) => $"{key}-frontend-cluster";

    /// <summary>
    /// Rebuilds the route table from a reloaded configuration.
    /// </summary>
    /// <param name="config">The reloaded configuration.</param>
    /// <remarks>
    /// The route table is one of the four components that have to agree on what counts as an anonymous path
    /// (see <see cref="AnonymousPaths"/>). The other three are middlewares reading
    /// <see cref="IOptionsMonitor{TOptions}.CurrentValue"/> per request, so they follow a reload immediately;
    /// a table built once at startup would not. Withdrawing a declared prefix would leave it on a route still
    /// carrying <see cref="AnonymousAuthorizationPolicy"/> until the process restarted, and declaring a new one
    /// would leave it matching only the authenticated catch-all — agreement at the same startup rather than at
    /// the same instant.
    /// <para>
    /// A file-backed configuration source commonly raises two change notifications for a single edit, so a
    /// rebuild that arrives at the table already being served is skipped: handing YARP an identical
    /// configuration makes it tear down and rebuild its route table for nothing.
    /// </para>
    /// </remarks>
    void Rebuild(C.AuthProxy config)
    {
        var routes = BuildRoutes(config, _logger);
        var clusters = BuildClusters(config);

        lock (_rebuilding)
        {
            var current = _inner.GetConfig();

            if (current.Routes.SequenceEqual(routes) && current.Clusters.SequenceEqual(clusters))
            {
                return;
            }

            _inner.Update(routes, clusters);
        }
    }
}
