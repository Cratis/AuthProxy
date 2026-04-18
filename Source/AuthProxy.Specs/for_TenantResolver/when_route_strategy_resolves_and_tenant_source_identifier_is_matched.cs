// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_TenantResolver;

public class when_route_strategy_resolves_and_tenant_source_identifier_is_matched : Specification
{
    static readonly Guid _expectedTenantId = Guid.Parse("44444444-4444-4444-4444-444444444444");

    TenantResolver _resolver;
    DefaultHttpContext _context;
    bool _succeeded;
    Guid _tenantId;

    void Establish()
    {
        var config = new C.AuthProxy
        {
            Tenants = new C.Tenants
            {
                [_expectedTenantId] = new C.Tenant { Name = "Acme", SourceIdentifiers = ["tenant-abc"] }
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
        _context.Request.Path = "/tenant-abc/api";

        _resolver = new TenantResolver(optionsMonitor, [new RouteSourceIdentifierStrategy()], Substitute.For<ILogger<TenantResolver>>());
    }

    void Because() => _succeeded = _resolver.TryResolve(_context, out _tenantId);

    [Fact] void should_succeed() => _succeeded.ShouldBeTrue();
    [Fact] void should_return_the_matched_tenant_id() => _tenantId.ShouldEqual(_expectedTenantId);
}
