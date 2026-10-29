// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy.for_SelectedTenantCookie;

public class when_reading_a_cookie_written_for_the_signed_in_account : given.a_selected_tenant_cookie
{
    SelectedTenantCookieValue _value;

    void Establish()
    {
        var responder = SignedInAs("user-1");
        _cookie.TryWrite(responder, "tenant-a");
        _context = RequestCarrying(responder, "user-1");
    }

    DefaultHttpContext _context;

    void Because() => _value = _cookie.Read(_context);

    [Fact] void should_be_bound() => _value.State.ShouldEqual(SelectedTenantCookieState.Bound);
    [Fact] void should_name_the_selected_tenant() => _value.TenantId.ShouldEqual("tenant-a");
}
