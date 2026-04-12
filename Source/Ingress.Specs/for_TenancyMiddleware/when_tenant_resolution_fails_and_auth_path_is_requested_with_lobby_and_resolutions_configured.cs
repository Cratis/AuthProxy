// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.Ingress.for_TenancyMiddleware;

public class when_tenant_resolution_fails_and_auth_path_is_requested_with_lobby_and_resolutions_configured : Specification
{
    const string LobbyUrl = "http://lobby-service/";

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
            ],
            Invite = new InviteConfig
            {
                Lobby = new MicroserviceConfig
                {
                    Frontend = new MicroserviceEndpointConfig { BaseUrl = LobbyUrl }
                }
            }
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
            Substitute.For<ITenantVerifier>(),
            Substitute.For<IIdentityDetailsResolver>(),
            Substitute.For<IErrorPageProvider>(),
            Substitute.For<ILogger<TenancyMiddleware>>());

        _context = new DefaultHttpContext();
        _context.Request.Path = WellKnownPaths.Providers;
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_call_next() => _nextCalled.ShouldBeTrue();
    [Fact] void should_not_redirect_to_lobby() => _context.Response.Headers.Location.ToString().ShouldEqual(string.Empty);
    [Fact] void should_not_return_401() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status200OK);
}