// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.AccessTokens.for_UserTokenSessions;

public class when_a_session_is_signed_out : Specification
{
    IUserTokenStore _store;
    DefaultHttpContext _httpContext;

    void Establish()
    {
        _store = Substitute.For<IUserTokenStore>();
        _httpContext = new DefaultHttpContext { RequestServices = new ServiceCollection().AddSingleton(_store).BuildServiceProvider() };

        var properties = new AuthenticationProperties();
        properties.Items[UserTokenSessions.PropertiesKey] = "session-id";
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity("Cookies")), properties, "Cookies");
        UserTokenSessions.Remember(new CookieValidatePrincipalContext(_httpContext, new AuthenticationScheme("Cookies", null, typeof(CookieAuthenticationHandler)), new CookieAuthenticationOptions(), ticket));
    }

    Task Because() => UserTokenSessions.Forget(new CookieSigningOutContext(
        _httpContext,
        new AuthenticationScheme("Cookies", null, typeof(CookieAuthenticationHandler)),
        new CookieAuthenticationOptions(),
        new AuthenticationProperties(),
        new CookieOptions()));

    [Fact] void should_remove_the_token_session() => _store.Received(1).Remove("session-id", Arg.Any<CancellationToken>());
    [Fact] void should_forget_it_for_the_rest_of_the_request() => UserTokenSessions.Of(_httpContext).ShouldBeNull();
}
