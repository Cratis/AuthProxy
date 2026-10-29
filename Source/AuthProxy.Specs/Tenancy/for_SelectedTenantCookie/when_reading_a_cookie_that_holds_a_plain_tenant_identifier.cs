// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy.for_SelectedTenantCookie;

public class when_reading_a_cookie_that_holds_a_plain_tenant_identifier : given.a_selected_tenant_cookie
{
    SelectedTenantCookieValue _value;
    DefaultHttpContext _context;

    void Establish()
    {
        _context = SignedInAs("user-1");
        _context.Request.Headers.Cookie = $"{Cookies.Tenant}=tenant-a";
    }

    void Because() => _value = _cookie.Read(_context);

    [Fact] void should_be_reported_as_from_an_earlier_version() => _value.State.ShouldEqual(SelectedTenantCookieState.Legacy);
    [Fact] void should_name_the_tenant() => _value.TenantId.ShouldEqual("tenant-a");
}
