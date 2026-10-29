// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware;

public class when_a_user_without_tenants_has_a_pending_registration : given.a_tenant_selection_endpoint
{
    void Establish()
    {
        _endpointStatus = HttpStatusCode.OK;
        _endpointBody = "[]";
        _context.Request.Headers.Cookie = $"{Cookies.Registration}=pending";
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_continue() => _nextCalled.ShouldBeTrue();
    [Fact] void should_not_confirm_a_tenant() => Confirmed.ShouldEqual(string.Empty);
    [Fact] void should_not_call_the_tenant_endpoint() => _endpointCalls.ShouldEqual(0);
    [Fact] void should_not_offer_a_choice() => _errorPageProvider.DidNotReceive().WriteErrorPageAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<int>());

    string Confirmed => _context.Items.TryGetValue(SelectionSourceIdentifierStrategy.ConfirmedTenantItemKey, out var confirmed) ? confirmed as string ?? string.Empty : string.Empty;
    string SetCookies => _context.Response.Headers.SetCookie.ToString();
}
