// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Model;

namespace Cratis.AuthProxy.Authentication.for_ClientCredentialsServiceResolver;

public class when_the_selected_proxy_service_cannot_be_resolved : Specification
{
    ClientCredentialsServiceResolver _resolver;
    DefaultHttpContext _context;

    void Establish()
    {
        var config = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["machine"] = new()
                {
                    Backend = new C.ServiceEndpoint { BaseUrl = "http://machine.test/" },
                    ClientCredentials = new C.ServiceClientCredentials(),
                },
            },
        };
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(config);
        _resolver = new(monitor, Substitute.For<ILogger<ClientCredentialsServiceResolver>>());
        _context = new DefaultHttpContext();
        _context.Request.Path = "/api/orders";
        var route = new RouteModel(
            new RouteConfig { RouteId = "removed-route", ClusterId = "removed-backend-cluster" },
            new ClusterState("removed-backend-cluster"),
            HttpTransformer.Default);
        _context.SetEndpoint(new Endpoint(null, new EndpointMetadataCollection(route), "proxied"));
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("machine", null)]
    [InlineData(null, "?service=machine")]
    public void should_not_fall_back_to_a_client_credentials_candidate(string? header, string? query)
    {
        _context.Request.Headers[Headers.ServiceId] = header;
        _context.Request.QueryString = new QueryString(query);
        _resolver.TryResolveForRequest(_context.Request, out _).ShouldBeFalse();
    }
}
