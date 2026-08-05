// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;
using Yarp.ReverseProxy.Configuration;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.ReverseProxy;

/// <summary>
/// Builds and serves the YARP <see cref="IProxyConfig"/> dynamically from the
/// <see cref="C.AuthProxy.Services"/> configuration section.
///
/// <para>
/// Each microservice generates routes that are matched by either:
/// <list type="bullet">
///   <item>An <c>Microservice-ID</c> HTTP header set to the microservice name, or</item>
///   <item>A <c>microservice</c> query-string parameter set to the microservice name.</item>
/// </list>
/// </para>
/// <para>
/// When only a <b>single</b> microservice is configured the header / query parameter is
/// optional and a plain catch-all route is also registered so that the single
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
    /// The YARP well-known authorization policy name that disables authorization for a route.
    /// </summary>
    const string AnonymousAuthorizationPolicy = "anonymous";

    /// <summary>
    /// The path prefix served by a service's backend rather than its frontend.
    /// </summary>
    const string ApiPathPrefix = "/api";

    static readonly ClusterConfig _baseCluster = new()
    {
        HttpRequest = new() { ActivityTimeout = TimeSpan.FromMinutes(5) },
    };

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
        _inner = new InMemoryConfigProvider(
            BuildRoutes(config.CurrentValue, logger),
            BuildClusters(config.CurrentValue));
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
        var isSingleMicroservice = services.Count == 1;

        // A declared prefix is matched without any service-selection header or query parameter, so two
        // services declaring the same prefix would emit two routes with an identical template and an
        // identical order — which ASP.NET cannot choose between, and reports as AmbiguousMatchException on
        // the declared path. Claiming each prefix for the first service that can actually serve it keeps
        // the path anonymous, which is what every declaring service asked for, and the table unambiguous.
        var claimedAnonymousPaths = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var (name, ms) in services)
        {
            var key = name.ToLowerInvariant();

            routes.AddRange(AnonymousRoutes(key, ms, claimedAnonymousPaths, logger));

            if (ms.Backend is not null)
            {
                routes.AddRange(BackendRoutes(key, isSingleMicroservice));
            }

            if (ms.Frontend is not null)
            {
                routes.AddRange(FrontendRoutes(key));
            }
        }

        // In a single-microservice deployment also add a plain catch-all so the
        // frontend is reachable without any routing header or query parameter.
        if (isSingleMicroservice)
        {
            var (name, ms) = services.First();
            var key = name.ToLowerInvariant();

            if (ms.Frontend is not null)
            {
                routes.Add(new RouteConfig
                {
                    RouteId = $"{key}-frontend-catchall-default",
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
    /// Builds the routes for the paths a service declares in <see cref="C.Service.AnonymousPaths"/>.
    /// </summary>
    /// <param name="microserviceKey">The lower-cased service key.</param>
    /// <param name="service">The service configuration.</param>
    /// <param name="claimedPaths">The prefixes already claimed, keyed by the service serving each; claimed here as they are emitted.</param>
    /// <param name="logger">The logger, used to name a prefix an earlier service already claimed.</param>
    /// <returns>One route per declared anonymous path prefix not already claimed.</returns>
    /// <remarks>
    /// These are the only routes not generated with <c>AuthorizationPolicy = "default"</c>. That default is
    /// <c>RequireAuthenticatedUser()</c>, so without this a declared anonymous path clears
    /// <c>SelectProviderMiddleware</c> only to be stopped one step later — refused by authorization on the
    /// catch-all route in a single-service deployment, or matching no route at all in a multi-service one,
    /// where every other route is selected by a header or query parameter an anonymous caller has no reason
    /// to send. The same closed door either way. None of the built-in skip-list paths (invite,
    /// registration, authentication UI, <c>/_pages</c>) is ever proxied to a service, so this is the first
    /// case where an unauthenticated request is meant to reach a backend, and the first that needs the
    /// policy relaxed.
    /// <para>
    /// The relaxation is scoped to exactly the declared prefixes and nothing else: with no
    /// <c>AnonymousPaths</c> declared this yields no routes and the table is what it was before. Each
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
        string microserviceKey,
        C.Service service,
        Dictionary<string, string> claimedPaths,
        ILogger logger)
    {
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
            var prefersBackend = new PathString(path).StartsWithSegments(ApiPathPrefix);
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

            yield return new RouteConfig
            {
                RouteId = $"{microserviceKey}-anonymous-{index}",
                ClusterId = clusterId,
                AuthorizationPolicy = AnonymousAuthorizationPolicy,
                Match = new RouteMatch { Path = $"{path}/{{**catch-all}}" },
                Order = 0,
            };

            index++;
        }
    }

    static IEnumerable<RouteConfig> BackendRoutes(string microserviceKey, bool isSingle)
    {
        // Header-matched API route
        yield return new RouteConfig
        {
            RouteId = $"{microserviceKey}-backend-header-api",
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
            Order = 1,
        };

        // Query-parameter–matched API route (adds the header for downstream)
        yield return new RouteConfig
        {
            RouteId = $"{microserviceKey}-backend-query-api",
            ClusterId = BackendClusterId(microserviceKey),
            AuthorizationPolicy = "default",
            Match = new RouteMatch
            {
                Path = "/api/{**catch-all}",
                QueryParameters =
                [
                    new RouteQueryParameter
                    {
                        Name = "service",
                        Mode = QueryParameterMatchMode.Exact,
                        IsCaseSensitive = false,
                        Values = [microserviceKey],
                    }
                ],
            },
            Order = 1,
        };

        // Plain /api catch-all when there is only one microservice.
        if (isSingle)
        {
            yield return new RouteConfig
            {
                RouteId = $"{microserviceKey}-backend-api-default",
                ClusterId = BackendClusterId(microserviceKey),
                AuthorizationPolicy = "default",
                Match = new RouteMatch { Path = "/api/{**catch-all}" },
                Order = 50,
            };
        }
    }

    static IEnumerable<RouteConfig> FrontendRoutes(string microserviceKey)
    {
        // Header-matched frontend route
        yield return new RouteConfig
        {
            RouteId = $"{microserviceKey}-frontend-header",
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
            Order = 10,
        };

        // Query-parameter–matched frontend route
        yield return new RouteConfig
        {
            RouteId = $"{microserviceKey}-frontend-query",
            ClusterId = FrontendClusterId(microserviceKey),
            AuthorizationPolicy = "default",
            Match = new RouteMatch
            {
                Path = "/{**catch-all}",
                QueryParameters =
                [
                    new RouteQueryParameter
                    {
                        Name = "service",
                        Mode = QueryParameterMatchMode.Exact,
                        IsCaseSensitive = false,
                        Values = [microserviceKey],
                    }
                ],
            },
            Order = 10,
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
                clusters.Add(_baseCluster with
                {
                    ClusterId = BackendClusterId(key),
                    Destinations = new Dictionary<string, DestinationConfig>
                    {
                        ["destination1"] = new() { Address = ms.Backend.BaseUrl }
                    },
                });
            }

            if (ms.Frontend is not null)
            {
                clusters.Add(_baseCluster with
                {
                    ClusterId = FrontendClusterId(key),
                    Destinations = new Dictionary<string, DestinationConfig>
                    {
                        ["destination1"] = new() { Address = ms.Frontend.BaseUrl }
                    },
                });
            }
        }

        return clusters;
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
