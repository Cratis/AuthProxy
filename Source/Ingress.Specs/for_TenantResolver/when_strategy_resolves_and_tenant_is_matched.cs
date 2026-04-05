// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.Ingress.for_TenantResolver;

public class when_strategy_resolves_and_tenant_is_matched : Specification
{
    static readonly Guid _expectedTenantId = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");

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
                [_expectedTenantId] = new TenantConfig { Name = "Acme", Domains = ["acme.example.com"] }
            },
            TenantResolutions =
            [
                new TenantResolutionConfig { Strategy = Configuration.TenantSourceIdentifierResolverType.Host }
            ]
        };

        var optionsMonitor = Substitute.For<IOptionsMonitor<IngressConfig>>();
        optionsMonitor.CurrentValue.Returns(config);

        _context = new DefaultHttpContext();
        _context.Request.Host = new HostString("acme.example.com");

        _resolver = new TenantResolver(optionsMonitor, [new HostSourceIdentifierStrategy()], Substitute.For<ILogger<TenantResolver>>());
    }

    void Because() => _succeeded = _resolver.TryResolve(_context, out _tenantId);

    [Fact] void should_succeed() => Assert.True(_succeeded);
    [Fact] void should_return_the_matched_tenant_id() => Assert.Equal(_expectedTenantId, _tenantId);
}
