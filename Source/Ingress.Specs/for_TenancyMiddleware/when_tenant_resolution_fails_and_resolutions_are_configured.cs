// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.Ingress.for_TenancyMiddleware;

public class when_tenant_resolution_fails_and_resolutions_are_configured : Specification
{
    TenancyMiddleware _middleware;
    DefaultHttpContext _context;
    bool _nextCalled;

    void Establish()
    {
        var config = new IngressConfig
        {
            TenantResolutions =
            [
                new TenantResolutionConfig { Strategy = Configuration.TenantSourceIdentifierResolverType.Host }
            ]
        };
        var optionsMonitor = Substitute.For<IOptionsMonitor<IngressConfig>>();
        optionsMonitor.CurrentValue.Returns(config);

        var tenantResolver = Substitute.For<ITenantResolver>();
        tenantResolver.TryResolve(Arg.Any<HttpContext>(), out Arg.Any<Guid>()).Returns(false);

        _middleware = new TenancyMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            optionsMonitor,
            tenantResolver,
            Substitute.For<IIdentityDetailsResolver>(),
            Substitute.For<ILogger<TenancyMiddleware>>());

        _context = new DefaultHttpContext();
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_return_401() => Assert.Equal(StatusCodes.Status401Unauthorized, _context.Response.StatusCode);
    [Fact] void should_not_call_next() => Assert.False(_nextCalled);
}
