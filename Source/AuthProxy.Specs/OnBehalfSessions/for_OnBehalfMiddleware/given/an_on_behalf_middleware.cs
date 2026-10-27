// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.given;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Model;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfMiddleware.given;

public class an_on_behalf_middleware : Specification
{
    protected OnBehalfConfiguration _configuration;
    protected IOnBehalfSessions _sessions;
    protected IErrorPageProvider _errorPages;
    protected OnBehalfMiddleware _middleware;
    protected DefaultHttpContext _context;
    protected bool _nextCalled;

    void Establish()
    {
        _configuration = new();
        _sessions = Substitute.For<IOnBehalfSessions>();
        _sessions.Resolve(Arg.Any<HttpContext>()).Returns(OnBehalfResolution.None);
        _errorPages = Substitute.For<IErrorPageProvider>();
        _middleware = new(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            _configuration.Monitor,
            _sessions,
            _errorPages);
        _context = new DefaultHttpContext { User = Sessions.ActorPrincipal() };
        _context.Response.Body = new MemoryStream();
        _context.Request.Path = "/api/orders";
    }

    protected void PostStart(string body, string contentType = "application/json")
    {
        _context.Request.Method = HttpMethods.Post;
        _context.Request.Path = WellKnownPaths.OnBehalfStart;
        _context.Request.ContentType = contentType;
        _context.Request.Body = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(body));
    }

    protected void RouteTo(string service)
    {
        _configuration.Value.Services.TryAdd(service, new() { Backend = new() { BaseUrl = $"https://{service}.internal" } });
        var route = new RouteConfig { RouteId = $"{service}-route", ClusterId = $"{service.ToLowerInvariant()}-backend-cluster" };
        _context.SetEndpoint(new Endpoint(null, new EndpointMetadataCollection(new RouteModel(route, new ClusterState(route.ClusterId), HttpTransformer.Default)), "proxied"));
    }

    protected string ResponseBody()
    {
        _context.Response.Body.Position = 0;
        return new StreamReader(_context.Response.Body).ReadToEnd();
    }
}
