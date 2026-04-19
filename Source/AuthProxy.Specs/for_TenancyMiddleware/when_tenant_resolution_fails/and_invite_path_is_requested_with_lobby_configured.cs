// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_TenancyMiddleware.when_tenant_resolution_fails;

public class and_invite_path_is_requested_with_lobby_configured : Specification
{
    const string LobbyUrl = "http://lobby-service/";

    TenancyMiddleware _middleware;
    DefaultHttpContext _context;
    bool _nextCalled;

    void Establish()
    {
        var config = new C.AuthProxy
        {
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
        tenantResolver.TryResolve(Arg.Any<HttpContext>(), out Arg.Any<string>()).Returns(false);

        _middleware = new TenancyMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            optionsMonitor,
            tenantResolver,
            Substitute.For<ITenantVerifier>(),
            Substitute.For<IErrorPageProvider>(),
            Substitute.For<ILogger<TenancyMiddleware>>());

        _context = new DefaultHttpContext();
        _context.Request.Path = "/invite/some-token";
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_call_next() => _nextCalled.ShouldBeTrue();
    [Fact] void should_not_redirect_to_lobby() => _context.Response.Headers.Location.ToString().ShouldEqual(string.Empty);
}
