// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_AdditionalLogoutCookies;

public class when_clearing_a_cookie_with_a_domain : Specification
{
    DefaultHttpContext _context;
    string _setCookies;

    void Establish()
    {
        _context = new DefaultHttpContext();
        _context.Request.Scheme = "https";
        _context.Request.Host = new HostString("app.cratis.studio");
    }

    void Because()
    {
        AdditionalLogoutCookies.Clear(_context, [new C.LogoutCookie { Name = "_oauth2_proxy_admin", Domain = ".cratis.studio" }]);
        _setCookies = _context.Response.Headers.SetCookie.ToString();
    }

    [Fact] void should_delete_the_cookie_for_the_request_host() => _setCookies.ShouldContain("_oauth2_proxy_admin=; expires");
    [Fact] void should_delete_the_cookie_for_the_configured_domain() => _setCookies.ShouldContain("domain=.cratis.studio");
    [Fact] void should_delete_at_the_root_path() => _setCookies.ShouldContain("path=/");
    [Fact] void should_mark_the_deletions_secure() => _setCookies.ShouldContain("secure");

    [Fact]
    void should_emit_a_host_scoped_and_a_domain_scoped_deletion() =>
        _context.Response.Headers.SetCookie.Count.ShouldEqual(2);
}
