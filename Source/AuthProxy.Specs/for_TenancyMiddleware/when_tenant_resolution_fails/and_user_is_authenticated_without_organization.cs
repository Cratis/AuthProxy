// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_TenancyMiddleware.when_tenant_resolution_fails;

public class and_user_is_authenticated_without_organization : Specification
{
    TenancyMiddleware _middleware;
    DefaultHttpContext _context;
    IErrorPageProvider _errorPageProvider;
    bool _nextCalled;

    void Establish()
    {
        var config = new C.AuthProxy
        {
            TenantResolutions =
            [
                new C.TenantResolution { Strategy = C.TenantSourceIdentifierResolverType.Host }
            ]
        };
        var optionsMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        optionsMonitor.CurrentValue.Returns(config);

        var tenantResolver = Substitute.For<ITenantResolver>();
        tenantResolver.TryResolve(Arg.Any<HttpContext>(), out Arg.Any<string>()).Returns(false);

        _errorPageProvider = Substitute.For<IErrorPageProvider>();

        _middleware = new TenancyMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            optionsMonitor,
            tenantResolver,
            Substitute.For<ITenantVerifier>(),
            _errorPageProvider,
            Substitute.For<ILogger<TenancyMiddleware>>());

        _context = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Name, "someone")], "TestAuth"))
        };
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] async Task should_write_the_no_organization_page() => await _errorPageProvider
        .Received(1)
        .WriteErrorPageAsync(_context, WellKnownPageNames.NoOrganization, StatusCodes.Status403Forbidden);

    [Fact] void should_not_call_next() => Assert.False(_nextCalled);
}
