// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Arc.Identity;

namespace Cratis.AuthProxy.for_TenancyMiddleware;

public class when_everything_succeeds : Specification
{
    const string TenantId = "dddddddd-dddd-dddd-dddd-dddddddddddd";

    TenancyMiddleware _middleware;
    DefaultHttpContext _context;
    bool _nextCalled;

    void Establish()
    {
        var config = new C.AuthProxy();
        var optionsMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        optionsMonitor.CurrentValue.Returns(config);

        var tenantResolver = Substitute.For<ITenantResolver>();
        tenantResolver
            .TryResolve(Arg.Any<HttpContext>(), out Arg.Any<string>())
            .Returns(call =>
            {
                call[1] = TenantId;
                return true;
            });

        var identityResolver = Substitute.For<IIdentityDetailsResolver>();
        identityResolver
            .Resolve(Arg.Any<HttpContext>(), Arg.Any<Identity.ClientPrincipal>(), Arg.Any<string>())
            .Returns(Task.FromResult(new IdentityProviderResult("user-id", "user-name", true, true, [], null!)));

        var tenantVerifier = Substitute.For<ITenantVerifier>();
        tenantVerifier.VerifyAsync(Arg.Any<string>()).Returns(Task.FromResult(true));

        _middleware = new TenancyMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            optionsMonitor,
            tenantResolver,
            tenantVerifier,
            identityResolver,
            Substitute.For<IErrorPageProvider>(),
            Substitute.For<ILogger<TenancyMiddleware>>());

        _context = new DefaultHttpContext();
        var identity = new ClaimsIdentity([new Claim("oid", "user-id")], "aad");
        _context.User = new ClaimsPrincipal(identity);
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_call_next() => Assert.True(_nextCalled);
    [Fact] void should_store_tenant_id_in_context_items() => Assert.Equal(TenantId, _context.Items[TenancyMiddleware.TenantIdItemKey]);
}
