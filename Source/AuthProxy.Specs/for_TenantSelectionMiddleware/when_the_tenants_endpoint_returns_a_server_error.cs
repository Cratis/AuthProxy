// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware;

public class when_the_tenants_endpoint_returns_a_server_error : given.a_tenant_selection_endpoint
{
    void Establish() => _endpointStatus = HttpStatusCode.InternalServerError;

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_prevent_caching() => _context.Response.Headers.CacheControl.ToString().ShouldEqual("no-store");
    [Fact] void should_respond_with_service_unavailable() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status503ServiceUnavailable);
    [Fact] void should_serve_the_service_unavailable_page() => _errorPageProvider.Received(1).WriteErrorPageAsync(_context, WellKnownPageNames.ServiceUnavailable, StatusCodes.Status503ServiceUnavailable);
    [Fact] void should_not_call_next() => _nextCalled.ShouldBeFalse();
    [Fact] void should_not_set_tenant_cookies() => _context.Response.Headers.SetCookie.ToString().ShouldBeEmpty();
}
