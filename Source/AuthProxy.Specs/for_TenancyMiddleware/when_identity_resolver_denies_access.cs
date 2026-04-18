// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Arc.Identity;

namespace Cratis.AuthProxy.for_TenancyMiddleware;

public class when_identity_resolver_denies_access : Specification
{
    TenancyMiddleware _middleware;
    DefaultHttpContext _context;
    bool _nextCalled;

    void Establish()
    {
        var tenantId = Guid.Parse("cccccccc-cccc-cccc-cccc-cccccccccccc");

        var config = new C.AuthProxy();
        var optionsMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        optionsMonitor.CurrentValue.Returns(config);

        var tenantResolver = Substitute.For<ITenantResolver>();
        tenantResolver
            .TryResolve(Arg.Any<HttpContext>(), out Arg.Any<Guid>())
            .Returns(call =>
            {
                call[1] = tenantId;
                return true;
            });

        var identityResolver = Substitute.For<IIdentityDetailsResolver>();
        identityResolver
            .Resolve(Arg.Any<HttpContext>(), Arg.Any<Identity.ClientPrincipal>(), Arg.Any<Guid>())
            .Returns(Task.FromResult(IdentityProviderResult.Unauthorized));

        var tenantVerifier = Substitute.For<ITenantVerifier>();
        tenantVerifier.VerifyAsync(Arg.Any<Guid>()).Returns(Task.FromResult(true));

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

    [Fact] void should_not_call_next() => Assert.False(_nextCalled);
}
