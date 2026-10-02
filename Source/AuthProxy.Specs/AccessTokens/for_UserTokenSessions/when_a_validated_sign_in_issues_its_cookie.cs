// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Cratis.AuthProxy.AccessTokens.for_UserTokenSessions;

public class when_a_validated_sign_in_issues_its_cookie : given.a_sign_in_redeeming_its_code
{
    async Task Because()
    {
        await UserTokenSessions.Capture(_context);
        await UserTokenSessions.Complete(new CookieSigningInContext(
            _context.HttpContext,
            new AuthenticationScheme("Cookies", null, typeof(CookieAuthenticationHandler)),
            new CookieAuthenticationOptions(),
            new ClaimsPrincipal(),
            _properties,
            new CookieOptions()));
    }

    [Fact] void should_store_the_refresh_token_after_validation() => _store.Received(1).Create(new UserTokenSession("workforce", "refresh-token"), Arg.Any<CancellationToken>());
    [Fact] void should_put_only_the_session_identifier_on_the_cookie() => _properties.Items[UserTokenSessions.PropertiesKey].ShouldEqual("session-id");
    [Fact] void should_put_no_tokens_on_the_cookie() => _properties.GetTokens().ShouldBeEmpty();
}
