// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Model;

namespace Cratis.AuthProxy.Authorization.for_AccessPolicy.given;

/// <summary>
/// A selected proxy endpoint targeting a service whose key uses a non-ASCII lowercase mapping.
/// </summary>
public class a_selected_proxy_route : an_access_policy
{
    protected C.AuthProxy _config;
    protected AccessDecision _decision;

    void Establish()
    {
        CallerCarrying();
        _config = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["\u212Aey"] = new()
                {
                    Hosts = ["admin.example.com"],
                    PathPrefix = "/admin",
                    Backend = new C.ServiceEndpoint { BaseUrl = "http://backend.test/" },
                    Frontend = new C.ServiceEndpoint { BaseUrl = "http://frontend.test/" },
                    Authorization = new C.Authorization { RequiredClaims = [Claiming("role", "admin")] }
                }
            }
        };
        _context.Request.Host = new HostString("admin.example.com");
        _context.Request.Path = "/admin/api/users";
    }

    /// <summary>
    /// Selects a proxy endpoint with the given cluster.
    /// </summary>
    /// <param name="clusterId">The selected cluster identifier.</param>
    protected void SelectCluster(string clusterId)
    {
        var route = new RouteModel(
            new RouteConfig
            {
                RouteId = "route",
                ClusterId = clusterId,
                Match = new RouteMatch { Path = "/admin/{**catch-all}" }
            },
            new ClusterState(clusterId),
            HttpTransformer.Default);
        _context.SetEndpoint(new Endpoint(null, new EndpointMetadataCollection(route), "proxied"));
    }
}
