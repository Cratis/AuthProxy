// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware;

public class when_the_selected_tenant_was_confirmed_recently : given.a_tenant_selection_endpoint
{
    void Establish()
    {
        _endpointStatus = HttpStatusCode.OK;
        _endpointBody = """[{"id":"tenant-a","name":"tenant-a"}]""";
        _authProxyConfig.Session = new C.Session { TenantRevalidationInterval = TimeSpan.FromMinutes(10) };
        given.signed_selected_tenant_cookies.Seed(_context, "tenant-a");
        _middleware.InvokeAsync(_context).GetAwaiter().GetResult();
        _endpointCalls = 0;
        _nextCalled = false;
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_confirm_the_tenant() => Confirmed.ShouldEqual("tenant-a");
    [Fact] void should_continue() => _nextCalled.ShouldBeTrue();
    [Fact] void should_not_call_the_tenant_endpoint_again() => _endpointCalls.ShouldEqual(0);

    string Confirmed => _context.Items.TryGetValue(SelectionSourceIdentifierStrategy.ConfirmedTenantItemKey, out var confirmed) ? confirmed as string ?? string.Empty : string.Empty;
    string SetCookies => _context.Response.Headers.SetCookie.ToString();
}
