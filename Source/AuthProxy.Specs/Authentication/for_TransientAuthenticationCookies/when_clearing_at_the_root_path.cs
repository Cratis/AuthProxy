// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_TransientAuthenticationCookies;

public class when_clearing_at_the_root_path : Specification
{
    DefaultHttpContext _context;
    string _setCookies;

    void Establish()
    {
        _context = new DefaultHttpContext();
        _context.Request.Path = "/";
        _context.Request.Headers.Cookie = $"{Cookies.CorrelationPrefix}abc=one";
    }

    void Because()
    {
        TransientAuthenticationCookies.Clear(_context);
        _setCookies = _context.Response.Headers.SetCookie.ToString();
    }

    [Fact] void should_clear_the_correlation_cookie() => _setCookies.ShouldContain($"{Cookies.CorrelationPrefix}abc=; expires");

    [Fact]
    void should_only_emit_a_single_deletion() =>
        _context.Response.Headers.SetCookie.Count.ShouldEqual(1);
}
