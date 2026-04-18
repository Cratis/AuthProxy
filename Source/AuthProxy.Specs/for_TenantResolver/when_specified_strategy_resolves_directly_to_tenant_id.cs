// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_TenantResolver;

public class when_specified_strategy_resolves_directly_to_tenant_id : Specification
{
    static readonly Guid _expectedTenantId = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");

    TenantResolver _resolver;
    DefaultHttpContext _context;
    bool _succeeded;
    Guid _tenantId;

    void Establish()
    {
        var config = new C.AuthProxy
        {
            TenantResolutions =
            [
                new C.TenantResolution
                {
                    Strategy = C.TenantSourceIdentifierResolverType.Specified,
                    Options = new SpecifiedOptions { TenantId = _expectedTenantId.ToString() }
                }
            ]
        };

        var optionsMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        optionsMonitor.CurrentValue.Returns(config);

        _context = new DefaultHttpContext();

        _resolver = new TenantResolver(optionsMonitor, [new SpecifiedSourceIdentifierStrategy()], Substitute.For<ILogger<TenantResolver>>());
    }

    void Because() => _succeeded = _resolver.TryResolve(_context, out _tenantId);

    [Fact] void should_succeed() => Assert.True(_succeeded);
    [Fact] void should_return_the_specified_tenant_id() => Assert.Equal(_expectedTenantId, _tenantId);
}
