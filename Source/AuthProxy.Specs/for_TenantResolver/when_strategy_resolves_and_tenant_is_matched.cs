// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_TenantResolver;

public class when_strategy_resolves_and_tenant_is_matched : Specification
{
    const string ExpectedTenantId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";

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
                [ExpectedTenantId] = new C.Tenant { Name = "Acme", Domains = ["acme.example.com"] }
            },
            TenantResolutions =
            [
                new C.TenantResolution { Strategy = C.TenantSourceIdentifierResolverType.Host }
            ]
        };

        var optionsMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        optionsMonitor.CurrentValue.Returns(config);

        _context = new DefaultHttpContext();
        _context.Request.Host = new HostString("acme.example.com");

        _resolver = new TenantResolver(optionsMonitor, [new HostSourceIdentifierStrategy()], Substitute.For<ILogger<TenantResolver>>());
    }

    void Because() => _succeeded = _resolver.TryResolve(_context, out _tenantId);

    [Fact] void should_succeed() => Assert.True(_succeeded);
    [Fact] void should_return_the_matched_tenant_id() => Assert.Equal(ExpectedTenantId, _tenantId);
}
