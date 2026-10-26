// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions;

namespace Cratis.AuthProxy.for_TenancyMiddleware.when_acting_on_behalf_of_somebody.given;

public class an_on_behalf_request : Specification
{
    protected const string SessionTenant = "session-tenant";

    protected TenancyMiddleware _middleware;
    protected DefaultHttpContext _context;
    protected ITenantResolver _tenantResolver;
    protected IErrorPageProvider _errorPages;
    protected bool _nextCalled;

    void Establish()
    {
        var optionsMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        optionsMonitor.CurrentValue.Returns(new C.AuthProxy { TenantResolutions = [new C.TenantResolution()] });

        _tenantResolver = Substitute.For<ITenantResolver>();
        _errorPages = Substitute.For<IErrorPageProvider>();
        var tenantVerifier = Substitute.For<ITenantVerifier>();
        tenantVerifier.VerifyAsync(Arg.Any<string>(), Arg.Any<string?>()).Returns(true);

        _middleware = new TenancyMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            optionsMonitor,
            _tenantResolver,
            tenantVerifier,
            _errorPages,
            Substitute.For<ILogger<TenancyMiddleware>>());

        _context = new DefaultHttpContext();
        _context.SetOnBehalf(new OnBehalfContext(
            new OnBehalfSession("session-1", new OnBehalfActor("github", "actor", "actor@example.com"), SessionTenant, "user", "ISSUE-1", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1)),
            new ClientPrincipal { UserId = "user" },
            "actor",
            "assertion"));
    }

    protected void Resolves(string tenant, C.TenantSourceIdentifierResolverType strategy) =>
        _tenantResolver.TryResolve(Arg.Any<HttpContext>(), out Arg.Any<TenantResolutionResult>())
            .Returns(call =>
            {
                call[1] = new TenantResolutionResult(tenant, strategy);
                return true;
            });
}
