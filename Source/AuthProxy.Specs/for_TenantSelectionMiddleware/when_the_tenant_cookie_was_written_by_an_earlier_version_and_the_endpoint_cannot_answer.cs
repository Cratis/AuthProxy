// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware;

public class when_the_tenant_cookie_was_written_by_an_earlier_version_and_the_endpoint_cannot_answer : given.a_tenant_selection_endpoint
{
    void Establish()
    {
        _endpointStatus = null;
        given.signed_selected_tenant_cookies.SeedLegacy(_context, "tenant-a");
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_forward_the_request() => _nextCalled.ShouldBeFalse();
    [Fact] void should_not_confirm_a_tenant() => Confirmed.ShouldEqual(string.Empty);
    [Fact] void should_answer_service_unavailable() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status503ServiceUnavailable);
    [Fact] void should_not_reissue_the_cookie() => SetCookies.ShouldNotContain(Cookies.Tenant);

    string Confirmed => _context.Items.TryGetValue(SelectionSourceIdentifierStrategy.ConfirmedTenantItemKey, out var confirmed) ? confirmed as string ?? string.Empty : string.Empty;
    string SetCookies => _context.Response.Headers.SetCookie.ToString();
}
