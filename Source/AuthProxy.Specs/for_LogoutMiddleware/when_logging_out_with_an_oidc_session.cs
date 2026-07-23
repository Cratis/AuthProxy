// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Cratis.AuthProxy.for_LogoutMiddleware;

public class when_logging_out_with_an_oidc_session : Specification
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
        config.CurrentValue.Returns(new C.AuthProxy());

        _endSessionEndpointResolver = Substitute.For<IEndSessionEndpointResolver>();
        _endSessionEndpointResolver.Resolve("microsoft", Arg.Any<CancellationToken>()).Returns(EndSessionEndpoint);

        _middleware = new LogoutMiddleware(_ => Task.CompletedTask, config, _endSessionEndpointResolver, Substitute.For<ILogger<LogoutMiddleware>>());

        _context = new DefaultHttpContext();
        _context.Request.Scheme = "https";
        _context.Request.Host = new HostString("cratis.studio");
        _context.Request.Path = WellKnownPaths.Logout;
        _context.Request.QueryString = QueryString.Create("redirect", "https://cratis.studio");
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
    [Fact] void should_pass_the_id_token_hint() => _context.Response.Headers.Location.ToString().ShouldContain($"id_token_hint={IdToken}");
    [Fact] void should_pass_the_post_logout_redirect_uri_pointing_at_the_callback() => _context.Response.Headers.Location.ToString().ShouldContain($"post_logout_redirect_uri={Uri.EscapeDataString($"https://cratis.studio{WellKnownPaths.LogoutCallback}")}");
    [Fact] void should_carry_the_final_target_in_a_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain($"{Cookies.LogoutRedirect}=https");
    [Fact] void should_sign_out_of_the_authentication_cookie() => _authenticationService.Received(1).SignOutAsync(_context, CookieAuthenticationDefaults.AuthenticationScheme, Arg.Any<AuthenticationProperties>());
    [Fact] void should_clear_the_identity_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain($"{Cookies.Identity}=;");
}
