// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_TenantResolver;

public class when_subhost_strategy_resolves_and_verification_template_is_configured : Specification
{
    TenantResolver _resolver;
    DefaultHttpContext _context;
    bool _succeeded;
    string _tenantId = string.Empty;

    void Establish()
    {
        var config = new C.AuthProxy
        {
            TenantResolutions =
            [
                new C.TenantResolution
                {
                    Strategy = C.TenantSourceIdentifierResolverType.SubHost,
                    Options = new SubHostOptions
                    {
                        ParentHost = "example.com",
                        VerificationUrlTemplate = "https://tenant-registry.local/tenants/{tenantId}"
                    }
                }
            ]
        };

        var optionsMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        optionsMonitor.CurrentValue.Returns(config);

        _context = new DefaultHttpContext();
        _context.Request.Host = new HostString("acme.example.com");

        _resolver = new TenantResolver(optionsMonitor, [new SubHostSourceIdentifierStrategy()], Substitute.For<ILogger<TenantResolver>>());
    }

    void Because() => _succeeded = _resolver.TryResolve(_context, out _tenantId);

    [Fact] void should_succeed() => _succeeded.ShouldBeTrue();
    [Fact] void should_resolve_subhost_as_tenant_id() => _tenantId.ShouldEqual("acme");

    [Fact]
    void should_store_verification_template_in_http_context_items() =>
        _context.Items[TenancyMiddleware.TenantVerificationUrlTemplateItemKey]
            .ShouldEqual("https://tenant-registry.local/tenants/{tenantId}");
}
