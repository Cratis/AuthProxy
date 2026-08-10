// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_TransientAuthenticationCookies;

public class when_clearing_on_a_provider_callback_path : Specification
{
    DefaultHttpContext _context;
    string _setCookies;

    void Establish()
    {
        _context = new DefaultHttpContext();
        _context.Request.Path = "/signin-microsoft";
        _context.Request.Headers.Cookie =
            $"{Cookies.CorrelationPrefix}abc=one; {Cookies.NoncePrefix}def=two; keep-me=value";
    }

    void Because()
    {
        TransientAuthenticationCookies.Clear(_context);
        _setCookies = _context.Response.Headers.SetCookie.ToString();
    }

    [Fact] void should_clear_the_correlation_cookie_at_the_root_path() => _setCookies.ShouldContain($"{Cookies.CorrelationPrefix}abc=; expires");
    [Fact] void should_clear_the_nonce_cookie() => _setCookies.ShouldContain($"{Cookies.NoncePrefix}def=; expires");

    [Fact]
    void should_also_clear_at_the_callback_path_where_legacy_cookies_were_scoped() =>
        _setCookies.ShouldContain("path=/signin-microsoft");

    [Fact] void should_not_clear_unrelated_cookies() => _setCookies.ShouldNotContain("keep-me=;");
}
