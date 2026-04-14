// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_TenantResolver;

public class when_strategy_resolves_but_no_tenant_is_matched : Specification
{
    TenantResolver _resolver;
    DefaultHttpContext _context;
    bool _succeeded;
    Guid _tenantId;

    void Establish()
    {
        var config = new IngressConfig
        {
            Tenants = new TenantsConfig
            {
                [Guid.NewGuid()] = new TenantConfig { Name = "Acme", Domains = ["acme.example.com"] }
            },
            TenantResolutions =
            [
                new TenantResolutionConfig { Strategy = TenantSourceIdentifierResolverType.Host }
            ]
        };

        var optionsMonitor = Substitute.For<IOptionsMonitor<IngressConfig>>();
        optionsMonitor.CurrentValue.Returns(config);

        _context = new DefaultHttpContext();
        _context.Request.Host = new HostString("unknown.example.com");

        _resolver = new TenantResolver(optionsMonitor, [new HostSourceIdentifierStrategy()], Substitute.For<ILogger<TenantResolver>>());
    }

    void Because() => _succeeded = _resolver.TryResolve(_context, out _tenantId);

    [Fact] void should_not_succeed() => Assert.False(_succeeded);
    [Fact] void should_return_empty_tenant_id() => Assert.Equal(Guid.Empty, _tenantId);
}
