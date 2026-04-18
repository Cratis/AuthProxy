// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_TenantResolver;

public class when_subhost_strategy_resolves_directly_to_tenant_id : Specification
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
                    Options = new SubHostOptions { ParentHost = "example.com" }
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
    [Fact] void should_return_the_subhost_as_tenant_id() => _tenantId.ShouldEqual("acme");
}
