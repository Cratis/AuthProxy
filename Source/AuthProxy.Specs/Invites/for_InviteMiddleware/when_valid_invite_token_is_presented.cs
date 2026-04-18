// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware;

public class when_valid_invite_token_is_presented : Specification
{
    InviteMiddleware _middleware;
    DefaultHttpContext _context;
    Microsoft.AspNetCore.Authentication.IAuthenticationService _authService;
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

        _middleware = new InviteMiddleware(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            tokenValidator,
            optionsMonitor,
            CreateSingleProviderAuthConfig(),
            Substitute.For<IHttpClientFactory>(),
            Substitute.For<IErrorPageProvider>(),
            Substitute.For<ILogger<InviteMiddleware>>());

        _context = new DefaultHttpContext();
        _context.Request.Path = "/invite/some-token";

        // Provide a minimal authentication service so ChallengeAsync does not throw.
        _authService = Substitute.For<Microsoft.AspNetCore.Authentication.IAuthenticationService>();
        _authService
            .ChallengeAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<Microsoft.AspNetCore.Authentication.AuthenticationProperties>())
            .Returns(Task.CompletedTask);
        var serviceProvider = Substitute.For<IServiceProvider>();
        serviceProvider.GetService(typeof(Microsoft.AspNetCore.Authentication.IAuthenticationService)).Returns(_authService);
        _context.RequestServices = serviceProvider;
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_call_next() => _nextCalled.ShouldBeFalse();
    [Fact] void should_set_invite_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain(Cookies.InviteToken);
    [Fact]
    void should_challenge_the_single_provider_scheme() =>
        _authService.Received(1).ChallengeAsync(
            _context,
            OidcProviderScheme.FromName("Microsoft"),
            Arg.Is<Microsoft.AspNetCore.Authentication.AuthenticationProperties>(properties => properties.RedirectUri == "/invite/some-token"));

    static IOptionsMonitor<C.Authentication> CreateSingleProviderAuthConfig()
    {
        var monitor = Substitute.For<IOptionsMonitor<C.Authentication>>();
        monitor.CurrentValue.Returns(new C.Authentication
        {
            OidcProviders = [new C.OidcProvider { Name = "Microsoft", Authority = "https://login.microsoftonline.com/tenant/v2.0", ClientId = "client-id", ClientSecret = "secret" }]
        });
        return monitor;
    }
}
