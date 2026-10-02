// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Cratis.AuthProxy.AccessTokens.for_UserTokenSessions;

public class when_a_sign_in_replaces_an_existing_session : given.a_sign_in_redeeming_its_code
{
    async Task Because()
    {
        _context.HttpContext.Request.Headers.Cookie = ".AuthProxy=old-cookie";
        var previousProperties = new AuthenticationProperties();
        previousProperties.Items[UserTokenSessions.PropertiesKey] = "previous-session";
        _authentication.AuthenticateAsync(_context.HttpContext, "Cookies").Returns(AuthenticateResult.Success(
            new AuthenticationTicket(new ClaimsPrincipal(), previousProperties, "Cookies")));
        await UserTokenSessions.Capture(_context);
        await UserTokenSessions.Complete(new CookieSigningInContext(
            _context.HttpContext,
            new AuthenticationScheme("Cookies", null, typeof(CookieAuthenticationHandler)),
            new CookieAuthenticationOptions { Cookie = new CookieBuilder { Name = ".AuthProxy" } },
            new ClaimsPrincipal(),
            _properties,
            new CookieOptions()));
    }

    [Fact] void should_remove_the_previous_token_session() => _store.Received(1).Remove("previous-session", CancellationToken.None);
    [Fact] void should_keep_only_the_new_identifier() => _properties.Items[UserTokenSessions.PropertiesKey].ShouldEqual("session-id");
}
