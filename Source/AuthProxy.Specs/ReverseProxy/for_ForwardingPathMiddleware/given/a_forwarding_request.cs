// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Logging.Abstractions;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Model;

namespace Cratis.AuthProxy.ReverseProxy.for_ForwardingPathMiddleware.given;

public class a_forwarding_request : Specification
{
    protected DefaultHttpContext _context = new();
    protected C.AuthProxy _config = new() { Services = new Dictionary<string, C.Service> { ["app"] = new() { DeniedPaths = [new() { Path = "/api/private" }] } } };
    protected bool _continued;

    void Establish()
    {
        _context.Request.Path = "/api/private";
        _context.Request.Method = "GET";
        _context.Response.Body = new MemoryStream();
    }

    protected void Select(string cluster = "app-backend-cluster", string? prefix = null)
    {
        var route = new RouteModel(new RouteConfig
        {
            RouteId = "route",
            ClusterId = cluster,
            Metadata = prefix is null ? null : new Dictionary<string, string> { [ServiceRoutes.StripPathPrefixMetadataKey] = prefix }
        },
        new ClusterState(cluster),
        HttpTransformer.Default);
        _context.Features.Set<IReverseProxyFeature>(new ReverseProxyFeature { Route = route });
        _context.SetEndpoint(new Endpoint(_ => Task.CompletedTask, new EndpointMetadataCollection(route), "selected"));
    }

    protected Task Invoke()
    {
        _continued = false;
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(_config);
        return new ForwardingPathMiddleware(Continue, monitor, NullLogger<ForwardingPathMiddleware>.Instance).InvokeAsync(_context);
    }

    Task Continue(HttpContext context)
    {
        _continued = true;
        return Task.CompletedTask;
    }

    protected void AssertDenied()
    {
        _continued.ShouldBeFalse();
        _context.Response.StatusCode.ShouldEqual(404);
        _context.Response.ContentType.ShouldEqual(UniformDenial.ContentType);
        _context.Response.Headers.CacheControl.ToString().ShouldEqual(UniformDenial.CacheControl);
        _context.Response.Headers.ContainsKey("WWW-Authenticate").ShouldBeFalse();
        _context.Response.Headers.ContainsKey("Allow").ShouldBeFalse();
        _context.Response.Headers.ContainsKey("Location").ShouldBeFalse();
        _context.Response.Headers.ContainsKey("Set-Cookie").ShouldBeFalse();
        _context.Response.Body.Position = 0;
        new StreamReader(_context.Response.Body).ReadToEnd().ShouldEqual(_context.Request.Method == "HEAD" ? string.Empty : UniformDenial.Body);
    }
}
