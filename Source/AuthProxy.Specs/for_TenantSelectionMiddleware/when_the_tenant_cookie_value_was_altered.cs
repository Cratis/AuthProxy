// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware;

public class when_the_tenant_cookie_value_was_altered : given.a_tenant_selection_endpoint
{
    void Establish()
    {
        _endpointStatus = HttpStatusCode.OK;
        _endpointBody = """[{"id":"tenant-a","name":"tenant-a"},{"id":"tenant-b","name":"tenant-b"}]""";
        given.signed_selected_tenant_cookies.Seed(_context, "tenant-a");
        _context.Request.Headers.Cookie = _context.Request.Headers.Cookie.ToString() + "x";
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_confirm_a_tenant() => Confirmed.ShouldEqual(string.Empty);
    [Fact] void should_delete_the_selected_tenant_cookie() => SetCookies.ShouldContain($"{Cookies.Tenant}=;");
    [Fact] void should_offer_the_tenant_choice() => _errorPageProvider.Received(1).WriteErrorPageAsync(Arg.Any<HttpContext>(), WellKnownPageNames.SelectTenant, StatusCodes.Status200OK);

    string Confirmed => _context.Items.TryGetValue(SelectionSourceIdentifierStrategy.ConfirmedTenantItemKey, out var confirmed) ? confirmed as string ?? string.Empty : string.Empty;
    string SetCookies => _context.Response.Headers.SetCookie.ToString();
}
