// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_TenancyMiddleware;

public class when_strategy_sets_verification_url_template_override : Specification
{
    TenancyMiddleware _middleware;
    DefaultHttpContext _context;
    ITenantVerifier _tenantVerifier;

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
                var context = (HttpContext)call[0];
                context.Items[TenancyMiddleware.TenantVerificationUrlTemplateItemKey] = "https://tenant-registry.local/{tenantId}";
                call[1] = "acme";
                return true;
            });

        _tenantVerifier = Substitute.For<ITenantVerifier>();
        _tenantVerifier.VerifyAsync(Arg.Any<string>(), Arg.Any<string?>()).Returns(Task.FromResult(true));

        _middleware = new TenancyMiddleware(
            _ => Task.CompletedTask,
            optionsMonitor,
            tenantResolver,
            _tenantVerifier,
            Substitute.For<IErrorPageProvider>(),
            Substitute.For<ILogger<TenancyMiddleware>>());

        _context = new DefaultHttpContext();
    }

    Task Because() => _middleware.InvokeAsync(_context);

    [Fact]
    void should_forward_strategy_override_to_verifier() =>
        _tenantVerifier.Received(1).VerifyAsync("acme", "https://tenant-registry.local/{tenantId}");
}
