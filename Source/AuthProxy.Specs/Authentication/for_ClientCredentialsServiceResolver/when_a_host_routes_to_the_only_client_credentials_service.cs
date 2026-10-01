// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_ClientCredentialsServiceResolver;

public class when_a_host_routes_to_the_only_client_credentials_service : Specification
{
    ClientCredentialsServiceResolver _resolver;
    DefaultHttpContext _context;
    bool _resolved;
    ConfiguredClientCredentialsService _service;

    void Establish()
    {
        var config = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["billing"] = new()
                {
                    Hosts = ["billing.example.com"],
                    Backend = new C.ServiceEndpoint { BaseUrl = "http://billing.test/" },
                    ClientCredentials = new C.ServiceClientCredentials(),
                },
                ["portal"] = new()
                {
                    Backend = new C.ServiceEndpoint { BaseUrl = "http://portal.test/" },
                },
            },
        };
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(config);
        _resolver = new(monitor, Substitute.For<ILogger<ClientCredentialsServiceResolver>>());

        _context = new DefaultHttpContext();
        _context.Request.Host = new HostString("billing.example.com");
        _context.Request.Path = "/api/invoices";
    }

    void Because() => _resolved = _resolver.TryResolveForRequest(_context.Request, out _service);

    [Fact] void should_resolve_the_service() => _resolved.ShouldBeTrue();
    [Fact] void should_resolve_the_service_the_host_routes_to() => _service.Name.ShouldEqual("billing");
}
