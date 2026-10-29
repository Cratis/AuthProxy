// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware;

public class when_the_selected_tenant_cannot_be_confirmed_because_the_answer_is_unreadable : given.a_tenant_selection_endpoint
{
    void Establish()
    {
        _endpointStatus = HttpStatusCode.OK;
        _endpointBody = "not json";
        given.signed_selected_tenant_cookies.Seed(_context, "tenant-a");
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_forward_the_request() => _nextCalled.ShouldBeFalse();
    [Fact] void should_not_confirm_a_tenant() => Confirmed.ShouldEqual(string.Empty);
    [Fact] void should_answer_service_unavailable() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status503ServiceUnavailable);
    [Fact] void should_not_cache_the_answer() => _context.Response.Headers.CacheControl.ToString().ShouldEqual("no-store");
    [Fact] void should_keep_the_selected_tenant_cookie() => SetCookies.ShouldNotContain($"{Cookies.Tenant}=;");

    string Confirmed => _context.Items.TryGetValue(SelectionSourceIdentifierStrategy.ConfirmedTenantItemKey, out var confirmed) ? confirmed as string ?? string.Empty : string.Empty;
    string SetCookies => _context.Response.Headers.SetCookie.ToString();
}
