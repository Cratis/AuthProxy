// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Ingress.Configuration;
using Microsoft.Extensions.Options;
using Yarp.ReverseProxy.Configuration;

namespace Cratis.Ingress.ReverseProxy;

/// <summary>
/// Builds and serves the YARP <see cref="IProxyConfig"/> dynamically from the
/// <see cref="IngressConfig.Microservices"/> configuration section.
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
/// </summary>
/// <param name="config">The options monitor providing the current ingress configuration.</param>
public class MicroserviceReverseProxyConfigProvider(
    IOptionsMonitor<IngressConfig> config) : IProxyConfigProvider
{
    static readonly ClusterConfig _baseCluster = new()
    {
        HttpRequest = new() { ActivityTimeout = TimeSpan.FromMinutes(5) },
    };

    readonly InMemoryConfigProvider _inner = new(
        BuildRoutes(config.CurrentValue),
        BuildClusters(config.CurrentValue));

    /// <inheritdoc/>
    public IProxyConfig GetConfig() => _inner.GetConfig();

    static List<RouteConfig> BuildRoutes(IngressConfig config)
    {
        var routes = new List<RouteConfig>();
        var microservices = config.Microservices;
        var isSingleMicroservice = microservices.Count == 1;

        foreach (var (name, ms) in microservices)
        {
            var key = name.ToLowerInvariant();

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
            var (name, ms) = microservices.First();
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
                        Name = Headers.MicroserviceId,
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
                        Name = "microservice",
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
                        Name = Headers.MicroserviceId,
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
                        Name = "microservice",
                        Mode = QueryParameterMatchMode.Exact,
                        IsCaseSensitive = false,
                        Values = [microserviceKey],
                    }
                ],
            },
            Order = 10,
        };
    }

    static List<ClusterConfig> BuildClusters(IngressConfig config)
    {
        var clusters = new List<ClusterConfig>();
        foreach (var (name, ms) in config.Microservices)
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
}
