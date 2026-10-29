// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy.for_SelectedTenantCookie;

public class when_reading_a_request_without_the_cookie : given.a_selected_tenant_cookie
{
    SelectedTenantCookieValue _value;

    void Because() => _value = _cookie.Read(SignedInAs("user-1"));

    [Fact] void should_report_none() => _value.State.ShouldEqual(SelectedTenantCookieState.None);
}
