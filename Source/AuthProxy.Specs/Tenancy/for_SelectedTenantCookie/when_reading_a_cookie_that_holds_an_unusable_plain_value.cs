// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy.for_SelectedTenantCookie;

public class when_reading_a_cookie_that_holds_an_unusable_plain_value : given.a_selected_tenant_cookie
{
    SelectedTenantCookieValue _value;
    DefaultHttpContext _context;

    void Establish()
    {
        _context = SignedInAs("user-1");
        _context.Request.Headers.Cookie = $"{Cookies.Tenant}=a/b";
    }

    void Because() => _value = _cookie.Read(_context);

    [Fact] void should_be_invalid() => _value.State.ShouldEqual(SelectedTenantCookieState.Invalid);
}
