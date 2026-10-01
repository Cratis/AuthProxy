// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_ClientCredentialsServiceResolver;

public class when_hosts_distinguish_services_with_the_same_token_prefix : Specification
{
    ClientCredentialsServiceResolver _resolver;
    DefaultHttpContext _context;

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
                ["reports"] = new()
                {
                    Hosts = ["reports.example.com"],
                    Backend = new C.ServiceEndpoint { BaseUrl = "http://reports.test/" },
                    ClientCredentials = new C.ServiceClientCredentials(),
                },
            },
        };
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(config);
        _resolver = new(monitor, Substitute.For<ILogger<ClientCredentialsServiceResolver>>());
        _context = new DefaultHttpContext();
    }

    [Theory]
    [InlineData("billing")]
    [InlineData("reports")]
    public void should_resolve_only_the_host_routed_service(string name)
    {
        _context.Request.Host = new HostString($"{name}.example.com");
        _context.Request.Path = "/api/orders";

        _resolver.TryResolveForRequest(_context.Request, out var service).ShouldBeTrue();

        service.Name.ShouldEqual(name);
    }

    [Fact]
    public void should_not_accept_a_path_outside_the_token_prefix()
    {
        _context.Request.Host = new HostString("billing.example.com");
        _context.Request.Path = "/dashboard";

        _resolver.TryResolveForRequest(_context.Request, out _).ShouldBeFalse();
    }
}
