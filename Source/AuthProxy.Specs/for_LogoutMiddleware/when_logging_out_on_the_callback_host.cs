// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Cratis.AuthProxy.for_LogoutMiddleware;

public class when_logging_out_on_the_callback_host : Specification
{
    const string EndSessionEndpoint = "https://login.microsoftonline.com/common/oauth2/v2.0/logout";
    const string IdToken = "the-id-token";

    LogoutMiddleware _middleware;
    DefaultHttpContext _context;
    IAuthenticationService _authenticationService;
    IEndSessionEndpointResolver _endSessionEndpointResolver;

    void Establish()
    {
        var config = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        config.CurrentValue.Returns(new C.AuthProxy
        {
            Session = new() { CookieDomain = ".example.test" },
            SignIn = new() { CallbackHost = "auth.example.test" },
            Services = new Dictionary<string, C.Service>
            {
                ["console"] = new() { Hosts = ["console.example.test"], Backend = new() { BaseUrl = "http://backend/" } },
                ["operations"] = new() { Hosts = ["operations.example.test"], Backend = new() { BaseUrl = "http://backend/" } }
            }
        });

        _endSessionEndpointResolver = Substitute.For<IEndSessionEndpointResolver>();
        _endSessionEndpointResolver.Resolve("microsoft", Arg.Any<CancellationToken>()).Returns(EndSessionEndpoint);

        _middleware = new LogoutMiddleware(_ => Task.CompletedTask, config, _endSessionEndpointResolver, Substitute.For<ILogger<LogoutMiddleware>>());

        _context = new DefaultHttpContext();
        _context.Request.Scheme = "https";
        _context.Request.Host = new HostString("auth.example.test");
        _context.Request.Path = WellKnownPaths.Logout;
        _context.Request.QueryString = QueryString.Create("redirect", "https://operations.example.test/goodbye");
        _context.Response.Body = new MemoryStream();

        var properties = new AuthenticationProperties();
        properties.StoreTokens([new AuthenticationToken { Name = "id_token", Value = IdToken }]);
        properties.Items[AuthenticationServiceCollectionExtensions.AuthenticationSchemeStateKey] = "microsoft";

        var ticket = new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity("test")), properties, CookieAuthenticationDefaults.AuthenticationScheme);

        _authenticationService = Substitute.For<IAuthenticationService>();
        _authenticationService.AuthenticateAsync(Arg.Any<HttpContext>(), CookieAuthenticationDefaults.AuthenticationScheme)
            .Returns(AuthenticateResult.Success(ticket));

        var serviceProvider = Substitute.For<IServiceProvider>();
        serviceProvider.GetService(typeof(IAuthenticationService)).Returns(_authenticationService);
        _context.RequestServices = serviceProvider;
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_respond_with_found() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status302Found);
    [Fact] void should_redirect_to_the_end_session_endpoint() => _context.Response.Headers.Location.ToString().ShouldContain(EndSessionEndpoint);
    [Fact] void should_pass_the_one_registered_post_logout_redirect_uri() => _context.Response.Headers.Location.ToString().ShouldContain($"post_logout_redirect_uri={Uri.EscapeDataString($"https://auth.example.test{WellKnownPaths.LogoutCallback}")}");
    [Fact] void should_carry_the_destination_on_this_host() => _context.Response.Headers.SetCookie.ToString().ShouldContain($"{Cookies.LogoutRedirect}=https");
    [Fact] void should_accept_a_destination_on_a_declared_host() => _context.Response.Headers.SetCookie.ToString().ShouldContain("operations.example.test");
    [Fact] void should_sign_out_of_the_authentication_cookie() => _authenticationService.Received(1).SignOutAsync(_context, CookieAuthenticationDefaults.AuthenticationScheme, Arg.Any<AuthenticationProperties>());
}
