// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware;

public class when_valid_invite_token_is_presented_with_multiple_providers : Specification
{
    InviteMiddleware _middleware;
    DefaultHttpContext _context;
    IErrorPageProvider _errorPageProvider;
    bool _nextCalled;

    void Establish()
    {
        var tokenValidator = Substitute.For<IInviteTokenValidator>();
        tokenValidator.ValidateDetailed(Arg.Any<string>()).Returns(InviteTokenValidationResult.Valid);

        var config = new C.AuthProxy
        {
            Invite = new C.Invite { ExchangeUrl = "http://studio/internal/invites/exchange" }
        };
        var optionsMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        optionsMonitor.CurrentValue.Returns(config);

        var authConfig = new C.Authentication
        {
            OidcProviders =
            [
                new C.OidcProvider { Name = "Microsoft", Authority = "https://login.microsoftonline.com/tenant/v2.0", ClientId = "client-id", ClientSecret = "secret" },
                new C.OidcProvider { Name = "Google", Authority = "https://accounts.google.com", ClientId = "google-id", ClientSecret = "google-secret" }
            ]
        };
        var authConfigMonitor = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authConfigMonitor.CurrentValue.Returns(authConfig);

        _errorPageProvider = Substitute.For<IErrorPageProvider>();

        _middleware = new InviteMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            tokenValidator,
            optionsMonitor,
            authConfigMonitor,
            Substitute.For<ITenantResolver>(),
            Substitute.For<IHttpClientFactory>(),
            _errorPageProvider,
            Substitute.For<ILogger<InviteMiddleware>>());

        _context = new DefaultHttpContext();
        _context.Request.Path = "/invite/some-token";
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_call_next() => _nextCalled.ShouldBeFalse();
    [Fact] void should_set_invite_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain(Cookies.InviteToken);
    [Fact] void should_set_providers_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain(Cookies.Providers);
    [Fact]
    void should_include_provider_names_in_providers_cookie() =>
        _context.Response.Headers.SetCookie.ToString().ShouldContain("Microsoft");
    [Fact]
    void should_serve_invitation_select_provider_page() =>
        _errorPageProvider.Received(1).WriteErrorPageAsync(
            _context,
            WellKnownPageNames.InvitationSelectProvider,
            StatusCodes.Status200OK);
}
