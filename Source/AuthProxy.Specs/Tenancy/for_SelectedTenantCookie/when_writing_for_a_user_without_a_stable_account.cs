// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy.for_SelectedTenantCookie;

public class when_writing_for_a_user_without_a_stable_account : given.a_selected_tenant_cookie
{
    bool _written;
    DefaultHttpContext _context;

    void Establish() => _context = new DefaultHttpContext();

    void Because() => _written = _cookie.TryWrite(_context, "tenant-a");

    [Fact] void should_not_write() => _written.ShouldBeFalse();
    [Fact] void should_not_set_a_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldBeEmpty();
}
