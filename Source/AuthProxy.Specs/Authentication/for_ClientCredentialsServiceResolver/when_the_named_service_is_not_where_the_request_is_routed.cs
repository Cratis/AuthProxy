// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_ClientCredentialsServiceResolver;

/// <summary>
/// A path prefix can route a request to a different service than the one its Service-ID header names. A token
/// scoped to the named service must not authenticate a request the route table sends somewhere else.
/// </summary>
public class when_the_named_service_is_not_where_the_request_is_routed : Specification
{
    ClientCredentialsServiceResolver _resolver;
    DefaultHttpContext _context;
    bool _resolved;

    void Establish()
    {
        var config = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["reports"] = new()
                {
                    PathPrefix = "/reports",
                    Backend = new C.ServiceEndpoint { BaseUrl = "http://reports.test/" },
                },
                ["portal"] = new()
                {
                    Backend = new C.ServiceEndpoint { BaseUrl = "http://portal.test/" },
                    ClientCredentials = new C.ServiceClientCredentials { RoutePrefix = "/reports/api" },
                },
            },
        };
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(config);
        _resolver = new(monitor, Substitute.For<ILogger<ClientCredentialsServiceResolver>>());

        _context = new DefaultHttpContext();
        _context.Request.Path = "/reports/api/orders";
        _context.Request.Headers[Headers.ServiceId] = "portal";
    }

    void Because() => _resolved = _resolver.TryResolveForRequest(_context.Request, out _);

    [Fact] void should_not_resolve_the_named_service() => _resolved.ShouldBeFalse();
}
