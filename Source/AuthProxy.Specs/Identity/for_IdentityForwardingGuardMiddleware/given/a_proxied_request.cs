// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Cratis.AuthProxy.given;
using Microsoft.AspNetCore.Authentication;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Model;

namespace Cratis.AuthProxy.Identity.for_IdentityForwardingGuardMiddleware.given;

public class a_proxied_request : Specification
{
    protected readonly RecordingLogger<IdentityForwardingGuardMiddleware> _logger = new();

    protected IdentityForwardingGuardMiddleware _middleware;
    protected DefaultHttpContext _context;
    protected bool _nextCalled;
    protected IAuthenticationService _authenticationService;
    protected ICanonicalIdentityResolver _canonicalIdentityResolver;

    void Establish()
    {
        _middleware = new IdentityForwardingGuardMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            _logger);

        _context = new DefaultHttpContext();
        _context.Request.Path = "/api/things";
        _context.Response.Body = new MemoryStream();

        _authenticationService = Substitute.For<IAuthenticationService>();
        _canonicalIdentityResolver = Substitute.For<ICanonicalIdentityResolver>();

        var serviceProvider = Substitute.For<IServiceProvider>();
        serviceProvider.GetService(typeof(IAuthenticationService)).Returns(_authenticationService);
        serviceProvider.GetService(typeof(ICanonicalIdentityResolver)).Returns(_canonicalIdentityResolver);
        _context.RequestServices = serviceProvider;

        SetProxyRoute("default");
    }

    protected void SetProxyRoute(string authorizationPolicy)
    {
        var route = new RouteModel(
            new RouteConfig
            {
                RouteId = "route",
                ClusterId = "cluster",
                AuthorizationPolicy = authorizationPolicy,
                Match = new RouteMatch { Path = "/{**catch-all}" }
            },
            new ClusterState("cluster"),
            HttpTransformer.Default);

        _context.SetEndpoint(new Endpoint(null, new EndpointMetadataCollection(route), "proxied"));
    }

    protected void SetAuthenticatedUser() =>
        _context.User = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("oid", "user-42"),
            new Claim("email", "user@example.com")
        ],
        "AuthenticationTypes.Federation"));
}
