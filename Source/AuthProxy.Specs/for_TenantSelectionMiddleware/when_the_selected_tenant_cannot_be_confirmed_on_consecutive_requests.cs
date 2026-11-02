// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware;

public class when_the_selected_tenant_cannot_be_confirmed_on_consecutive_requests : given.a_tenant_selection_endpoint
{
    void Establish()
    {
        _endpointStatus = null;
        given.signed_selected_tenant_cookies.Seed(_context, "tenant-a");
        _middleware.InvokeAsync(_context).GetAwaiter().GetResult();
        NextRequest();
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_ask_the_tenant_endpoint_again() => _endpointCalls.ShouldEqual(1);
    [Fact] void should_not_forward_the_request() => _nextCalled.ShouldBeFalse();
    [Fact] void should_not_confirm_a_tenant() => Confirmed.ShouldEqual(string.Empty);
    [Fact] void should_answer_service_unavailable() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status503ServiceUnavailable);

    string Confirmed => _context.Items.TryGetValue(SelectionSourceIdentifierStrategy.ConfirmedTenantItemKey, out var confirmed) ? confirmed as string ?? string.Empty : string.Empty;
    string SetCookies => _context.Response.Headers.SetCookie.ToString();

    void NextRequest()
    {
        var cookie = _context.Request.Headers.Cookie;
        _context = new DefaultHttpContext { User = _context.User };
        _context.Request.Path = "/products";
        _context.Request.Headers["Sec-Fetch-Dest"] = "document";
        _context.Request.Headers.Cookie = cookie;
        _context.Response.Body = new MemoryStream();
        _nextCalled = false;
        _endpointCalls = 0;
    }
}
