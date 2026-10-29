// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_TenantResolver;

public class when_a_route_segment_is_not_a_usable_tenant_identifier : Specification
{
    TenantResolver _resolver;
    DefaultHttpContext _context;
    bool _succeeded;
    string _tenantId = string.Empty;

    void Establish()
    {
        var config = new C.AuthProxy
        {
            Tenants = new C.Tenants
            {
                ["tenant-one"] = new C.Tenant { Name = "Acme", SourceIdentifiers = ["a b", "a/b", "tenant-abc"] }
            },
            TenantResolutions =
            [
                new C.TenantResolution
                {
                    Strategy = C.TenantSourceIdentifierResolverType.Route,
                    Options = new RouteOptions { Pattern = "/(?<sourceIdentifier>[^/]+)/" }
                }
            ]
        };

        var optionsMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        optionsMonitor.CurrentValue.Returns(config);

        _context = new DefaultHttpContext();
        _context.Request.Path = "/a b/api";
        _resolver = new TenantResolver(optionsMonitor, [new RouteSourceIdentifierStrategy()], Substitute.For<ILogger<TenantResolver>>());
    }

    void Because() => _succeeded = _resolver.TryResolve(_context, out _tenantId);

    [Fact] void should_not_resolve() => _succeeded.ShouldBeFalse();
    [Fact] void should_not_return_a_tenant() => _tenantId.ShouldEqual(string.Empty);
}
