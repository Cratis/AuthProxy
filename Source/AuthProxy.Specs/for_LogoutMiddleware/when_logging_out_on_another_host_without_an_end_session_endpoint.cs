// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Cratis.AuthProxy.for_LogoutMiddleware;

public class when_logging_out_on_another_host_without_an_end_session_endpoint : Specification
{
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
        _endSessionEndpointResolver.Resolve("microsoft", Arg.Any<CancellationToken>()).Returns(Task.FromResult<string?>(null));

        _middleware = new LogoutMiddleware(_ => Task.CompletedTask, config, _endSessionEndpointResolver, Substitute.For<ILogger<LogoutMiddleware>>());

        _context = new DefaultHttpContext();
        _context.Request.Scheme = "https";
        _context.Request.Host = new HostString("console.example.test");
        _context.Request.Path = WellKnownPaths.Logout;
        _context.Request.QueryString = QueryString.Create("redirect", "/goodbye");
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
    [Fact] void should_end_the_session_here_because_the_shared_cookie_is_deleted_for_every_host() => _authenticationService.Received(1).SignOutAsync(_context, CookieAuthenticationDefaults.AuthenticationScheme, Arg.Any<AuthenticationProperties>());
    [Fact] void should_redirect_straight_to_the_destination() => _context.Response.Headers.Location.ToString().ShouldEqual("/goodbye");
}
