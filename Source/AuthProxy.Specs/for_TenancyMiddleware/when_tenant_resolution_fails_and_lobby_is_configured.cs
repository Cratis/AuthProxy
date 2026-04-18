// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_TenancyMiddleware;

public class when_tenant_resolution_fails_and_lobby_is_configured : Specification
{
    const string LobbyUrl = "http://lobby-service/";

    TenancyMiddleware _middleware;
    DefaultHttpContext _context;
    bool _nextCalled;

    void Establish()
    {
        var config = new C.AuthProxy
        {
            TenantResolutions =
            [
                new C.TenantResolution { Strategy = C.TenantSourceIdentifierResolverType.Host }
            ],
            Invite = new C.Invite
            {
                Lobby = new C.Service
                {
                    Frontend = new C.ServiceEndpoint { BaseUrl = LobbyUrl }
                }
            }
        };
        var optionsMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
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
            Substitute.For<ITenantVerifier>(),
            Substitute.For<IIdentityDetailsResolver>(),
            Substitute.For<IErrorPageProvider>(),
            Substitute.For<ILogger<TenancyMiddleware>>());

        _context = new DefaultHttpContext();
        _context.Request.Path = "/some-page";
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_call_next() => _nextCalled.ShouldBeFalse();
    [Fact] void should_redirect_to_lobby() => _context.Response.Headers.Location.ToString().ShouldEqual(LobbyUrl);
}
