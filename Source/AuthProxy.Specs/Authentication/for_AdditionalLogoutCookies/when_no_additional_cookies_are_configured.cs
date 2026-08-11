// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_AdditionalLogoutCookies;

public class when_no_additional_cookies_are_configured : Specification
{
    DefaultHttpContext _context;

    void Establish()
    {
        _context = new DefaultHttpContext();
        _context.Request.Scheme = "https";
        _context.Request.Host = new HostString("app.cratis.studio");
    }

    void Because() => AdditionalLogoutCookies.Clear(_context, new C.Logout().AdditionalCookies);

    [Fact]
    void should_not_delete_anything() =>
        _context.Response.Headers.SetCookie.Count.ShouldEqual(0);
}
