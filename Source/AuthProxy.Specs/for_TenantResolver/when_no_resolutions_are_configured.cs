// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_TenantResolver;

public class when_no_resolutions_are_configured : Specification
{
    TenantResolver _resolver;
    DefaultHttpContext _context;
    bool _succeeded;
    string _tenantId = string.Empty;

    void Establish()
    {
        var config = new C.AuthProxy();
        var optionsMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        optionsMonitor.CurrentValue.Returns(config);

        _resolver = new TenantResolver(optionsMonitor, [], Substitute.For<ILogger<TenantResolver>>());
        _context = new DefaultHttpContext();
    }

    void Because() => _succeeded = _resolver.TryResolve(_context, out _tenantId);

    [Fact] void should_succeed() => Assert.True(_succeeded);
    [Fact] void should_return_empty_tenant_id() => Assert.Equal(string.Empty, _tenantId);
}
