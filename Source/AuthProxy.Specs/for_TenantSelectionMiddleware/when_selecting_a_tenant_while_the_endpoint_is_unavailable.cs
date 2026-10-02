// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware;

public class when_selecting_a_tenant_while_the_endpoint_is_unavailable : given.a_tenant_selection_endpoint
{
    void Establish()
    {
        _context.Request.Path = WellKnownPaths.SelectTenant;
        _context.Request.QueryString = new QueryString("?tenantId=tenant-a");
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_respond_with_service_unavailable() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status503ServiceUnavailable);
    [Fact] void should_serve_the_service_unavailable_page() => _errorPageProvider.Received(1).WriteErrorPageAsync(_context, WellKnownPageNames.ServiceUnavailable, StatusCodes.Status503ServiceUnavailable);
    [Fact] void should_not_call_next() => _nextCalled.ShouldBeFalse();
    [Fact] void should_not_set_tenant_cookies() => _context.Response.Headers.SetCookie.ToString().ShouldBeEmpty();
    [Fact] void should_not_redirect() => _context.Response.Headers.Location.ToString().ShouldBeEmpty();
}
