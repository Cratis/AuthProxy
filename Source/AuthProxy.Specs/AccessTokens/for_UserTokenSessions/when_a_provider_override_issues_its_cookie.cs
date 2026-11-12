// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Cratis.AuthProxy.AccessTokens.for_UserTokenSessions;

public class when_a_provider_override_issues_its_cookie : given.a_sign_in_redeeming_its_code
{
    [Theory]
    [InlineData(false, false, 2)]
    [InlineData(true, false, 12)]
    [InlineData(true, true, 2)]
    public async Task should_derive_retention_only_from_the_final_cookie_properties(bool globalSliding, bool allowRefresh, int hours)
    {
        _config.Session.SlidingExpiration = globalSliding;
        var issued = new DateTimeOffset(2026, 5, 1, 0, 0, 0, TimeSpan.Zero);
        _properties.IssuedUtc = issued;
        _properties.ExpiresUtc = issued.AddHours(hours);
        _properties.AllowRefresh = allowRefresh;
        await UserTokenSessions.Capture(_context);
        await UserTokenSessions.Complete(new CookieSigningInContext(
            _context.HttpContext,
            new AuthenticationScheme("Cookies", null, typeof(CookieAuthenticationHandler)),
            new CookieAuthenticationOptions(),
            new ClaimsPrincipal(),
            _properties,
            new CookieOptions()));
        await _store.Received(1).Create(
            Arg.Is<UserTokenSession>(session =>
            session.ExpiresAt == (allowRefresh ? null : issued.AddHours(hours))
            && session.Lifetime == TimeSpan.FromHours(hours) && session.Sliding == allowRefresh),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task should_not_touch_retention_when_the_cookie_forbids_refresh()
    {
        _context.HttpContext.Items[UserTokenSessions.HttpContextItemKey] = "session-id";
        _properties.AllowRefresh = false;
        await UserTokenSessions.RenewRetention(new CookieValidatePrincipalContext(
            _context.HttpContext,
            new AuthenticationScheme("Cookies", null, typeof(CookieAuthenticationHandler)),
            new CookieAuthenticationOptions { SlidingExpiration = true },
            new AuthenticationTicket(new ClaimsPrincipal(), _properties, "Cookies")));
        await _store.DidNotReceive().Get(Arg.Any<string>(), Arg.Any<CancellationToken>());
    }
}
