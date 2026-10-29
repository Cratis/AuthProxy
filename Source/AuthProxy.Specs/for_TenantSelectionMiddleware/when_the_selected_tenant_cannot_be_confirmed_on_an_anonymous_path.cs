// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware;

public class when_the_selected_tenant_cannot_be_confirmed_on_an_anonymous_path : given.a_tenant_selection_endpoint
{
    void Establish()
    {
        _endpointStatus = null;
        ServeAnonymousPath();
        _context.Request.Path = AnonymousPath;
        given.signed_selected_tenant_cookies.Seed(_context, "tenant-a");
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_continue() => _nextCalled.ShouldBeTrue();
    [Fact] void should_not_confirm_a_tenant() => Confirmed.ShouldEqual(string.Empty);
    [Fact] void should_keep_the_selected_tenant_cookie() => SetCookies.ShouldNotContain($"{Cookies.Tenant}=;");

    string Confirmed => _context.Items.TryGetValue(SelectionSourceIdentifierStrategy.ConfirmedTenantItemKey, out var confirmed) ? (string)confirmed : string.Empty;
    string SetCookies => _context.Response.Headers.SetCookie.ToString();
}
