// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy.for_SelectedTenantCookie;

public class when_writing_for_a_signed_in_account : given.a_selected_tenant_cookie
{
    DefaultHttpContext _context;

    void Establish() => _context = SignedInAs("user-1");

    void Because() => _cookie.TryWrite(_context, "tenant-a");

    [Fact] void should_write_a_protected_value() => _context.Response.Headers.SetCookie.ToString().ShouldContain($"{Cookies.Tenant}=%21");
    [Fact] void should_not_expose_the_tenant_in_the_value() => _context.Response.Headers.SetCookie.ToString().ShouldNotContain($"{Cookies.Tenant}=%21tenant-a");
    [Fact] void should_be_http_only() => _context.Response.Headers.SetCookie.ToString().ShouldContain("httponly");
}
