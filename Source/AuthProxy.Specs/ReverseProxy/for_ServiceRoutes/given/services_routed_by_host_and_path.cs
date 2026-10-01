// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ServiceRoutes.given;

/// <summary>
/// A deployment with a service at each routing step: a prefix on one host, the same prefix on every host, a host,
/// and a service reached only by name.
/// </summary>
public class services_routed_by_host_and_path : Specification
{
    protected C.AuthProxy _config;
    protected DefaultHttpContext _context;
    protected RoutedService? _result;

    void Establish()
    {
        _config = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["tenant-reports"] = new()
                {
                    Hosts = ["tenant.example.com"],
                    PathPrefix = "/reports",
                    Backend = new C.ServiceEndpoint { BaseUrl = "http://tenant-reports/" },
                },
                ["reports"] = new()
                {
                    PathPrefix = "/reports",
                    Backend = new C.ServiceEndpoint { BaseUrl = "http://reports-api/" },
                    Frontend = new C.ServiceEndpoint { BaseUrl = "http://reports-web/" },
                },
                ["billing"] = new()
                {
                    Hosts = ["billing.example.com"],
                    Backend = new C.ServiceEndpoint { BaseUrl = "http://billing-api/" },
                    Frontend = new C.ServiceEndpoint { BaseUrl = "http://billing-web/" },
                },
                ["portal"] = new()
                {
                    Backend = new C.ServiceEndpoint { BaseUrl = "http://portal-api/" },
                },
            },
        };
        _context = new DefaultHttpContext();
    }

    protected void Request(string host, string path)
    {
        _context.Request.Host = new HostString(host);
        _context.Request.Path = path;
    }

    protected void Resolve() => _result = ServiceRoutes.Resolve(_context.Request, _config);
}
