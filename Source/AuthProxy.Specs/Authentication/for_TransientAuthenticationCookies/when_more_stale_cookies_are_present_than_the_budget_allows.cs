// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_TransientAuthenticationCookies;

public class when_more_stale_cookies_are_present_than_the_budget_allows : Specification
{
    const int StaleCount = 20;

    DefaultHttpContext _context;
    int _measuredTotal;
    int _deleted;

    void Establish()
    {
        _context = new DefaultHttpContext();
        _context.Request.Path = "/signin-microsoft";
        var stale = Enumerable.Range(0, StaleCount).Select(index => $"{Cookies.NoncePrefix}{index:D3}{new string('x', 285)}=value");
        _context.Request.Headers.Cookie = string.Join("; ", stale.Append("keep-me=value"));
    }

    void Because()
    {
        TransientAuthenticationCookies.Clear(_context);
        var headers = _context.Response.Headers.SetCookie;
        SetCookieSizeMiddleware.TryMeasure(_context.Response.Headers, out _measuredTotal, out _);
        _deleted = headers.Count;
    }

    [Fact] void should_stay_within_the_sweep_budget() => _measuredTotal.ShouldBeLessThan(TransientAuthenticationCookies.SweepBudget + 1);
    [Fact] void should_clear_at_least_one_stale_cookie() => _deleted.ShouldBeGreaterThan(0);
    [Fact] void should_leave_the_rest_to_expire_on_their_own() => _deleted.ShouldBeLessThan(StaleCount);
    [Fact] void should_not_clear_unrelated_cookies() => _context.Response.Headers.SetCookie.ToString().ShouldNotContain("keep-me=;");
}
