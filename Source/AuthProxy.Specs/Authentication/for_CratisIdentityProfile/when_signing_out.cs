// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_CratisIdentityProfile;

public class when_signing_out : given.a_cratis_identity_realm
{
    const string IdToken = "the-cratis-identity-id-token";

    DefaultHttpContext _context;
    string _location;

    async Task Because()
    {
        var config = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        config.CurrentValue.Returns(new C.AuthProxy());
        var middleware = new LogoutMiddleware(
            _ => Task.CompletedTask,
            config,
            _services.GetRequiredService<IEndSessionEndpointResolver>(),
            _services.GetRequiredService<ILogger<LogoutMiddleware>>());

        var properties = new AuthenticationProperties();
        properties.StoreTokens([new AuthenticationToken { Name = "id_token", Value = IdToken }]);
        properties.Items[AuthenticationServiceCollectionExtensions.AuthenticationSchemeStateKey] = Scheme;
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity("test")), properties, CookieAuthenticationDefaults.AuthenticationScheme);

        var authentication = Substitute.For<IAuthenticationService>();
        authentication.AuthenticateAsync(Arg.Any<HttpContext>(), CookieAuthenticationDefaults.AuthenticationScheme)
            .Returns(AuthenticateResult.Success(ticket));
        var requestServices = Substitute.For<IServiceProvider>();
        requestServices.GetService(typeof(IAuthenticationService)).Returns(authentication);

        _context = NewContext();
        _context.RequestServices = requestServices;
        _context.Request.Path = WellKnownPaths.Logout;

        await middleware.InvokeAsync(_context);
        _location = _context.Response.Headers.Location.ToString();
    }

    [Fact] void should_redirect_to_the_discovered_end_session_endpoint() => _location.StartsWith($"{EndSessionEndpoint}?", StringComparison.Ordinal).ShouldBeTrue();
    [Fact] void should_pass_the_id_token_hint() => _location.ShouldContain($"id_token_hint={IdToken}");
    [Fact] void should_return_to_the_logout_callback() => _location.ShouldContain($"post_logout_redirect_uri={Uri.EscapeDataString($"https://studio.cratis.example{WellKnownPaths.LogoutCallback}")}");
    [Fact] void should_not_log_the_id_token() => _logs.Text.Contains(IdToken, StringComparison.Ordinal).ShouldBeFalse();
    [Fact] void should_not_log_the_client_secret() => _logs.Text.Contains(ClientSecret, StringComparison.Ordinal).ShouldBeFalse();
}
