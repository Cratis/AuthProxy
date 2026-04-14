// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.Ingress.for_TenancyMiddleware;

public class when_tenant_does_not_exist : Specification
{
    static readonly Guid _tenantId = Guid.Parse("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee");

    TenancyMiddleware _middleware;
    DefaultHttpContext _context;
    IErrorPageProvider _errorPageProvider;
    bool _nextCalled;

    void Establish()
    {
        var config = new IngressConfig();
        var optionsMonitor = Substitute.For<IOptionsMonitor<IngressConfig>>();
        optionsMonitor.CurrentValue.Returns(config);

        var tenantResolver = Substitute.For<ITenantResolver>();
        tenantResolver
            .TryResolve(Arg.Any<HttpContext>(), out Arg.Any<Guid>())
            .Returns(call =>
            {
                call[1] = _tenantId;
                return true;
            });

        var tenantVerifier = Substitute.For<ITenantVerifier>();
        tenantVerifier.VerifyAsync(_tenantId).Returns(Task.FromResult(false));

        _errorPageProvider = Substitute.For<IErrorPageProvider>();

        _middleware = new TenancyMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            optionsMonitor,
            tenantResolver,
            tenantVerifier,
            Substitute.For<IIdentityDetailsResolver>(),
            _errorPageProvider,
            Substitute.For<ILogger<TenancyMiddleware>>());

        _context = new DefaultHttpContext();
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_call_next() => _nextCalled.ShouldBeFalse();
    [Fact]
    void should_serve_tenant_not_found_page() =>
        _errorPageProvider.Received(1).WriteErrorPageAsync(
            _context,
            WellKnownPageNames.TenantNotFound,
            StatusCodes.Status404NotFound);
}
