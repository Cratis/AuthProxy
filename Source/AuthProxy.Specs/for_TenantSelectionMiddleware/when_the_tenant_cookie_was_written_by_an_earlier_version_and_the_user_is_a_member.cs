// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware;

public class when_the_tenant_cookie_was_written_by_an_earlier_version_and_the_user_is_a_member : given.a_tenant_selection_endpoint
{
    void Establish()
    {
        _endpointStatus = HttpStatusCode.OK;
        _endpointBody = """[{"id":"tenant-a","name":"tenant-a"}]""";
        given.signed_selected_tenant_cookies.SeedLegacy(_context, "tenant-a");
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_confirm_the_tenant() => Confirmed.ShouldEqual("tenant-a");
    [Fact] void should_continue() => _nextCalled.ShouldBeTrue();
    [Fact] void should_confirm_with_the_tenant_endpoint_once() => _endpointCalls.ShouldEqual(1);
    [Fact] void should_reissue_the_cookie_signed() => given.signed_selected_tenant_cookies.ReadBack(_context).ShouldEqual(new SelectedTenantCookieValue(SelectedTenantCookieState.Bound, "tenant-a"));

    string Confirmed => _context.Items.TryGetValue(SelectionSourceIdentifierStrategy.ConfirmedTenantItemKey, out var confirmed) ? (string)confirmed : string.Empty;
    string SetCookies => _context.Response.Headers.SetCookie.ToString();
}
