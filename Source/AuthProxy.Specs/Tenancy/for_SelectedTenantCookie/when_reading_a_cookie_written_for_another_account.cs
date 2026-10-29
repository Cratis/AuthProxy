// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy.for_SelectedTenantCookie;

public class when_reading_a_cookie_written_for_another_account : given.a_selected_tenant_cookie
{
    SelectedTenantCookieValue _value;
    DefaultHttpContext _context;

    void Establish()
    {
        var responder = SignedInAs("user-1");
        _cookie.TryWrite(responder, "tenant-a");
        _context = RequestCarrying(responder, "user-2");
    }

    void Because() => _value = _cookie.Read(_context);

    [Fact] void should_be_invalid() => _value.State.ShouldEqual(SelectedTenantCookieState.Invalid);
    [Fact] void should_not_name_a_tenant() => _value.TenantId.ShouldEqual(string.Empty);
}
