// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware;

public class when_the_tenants_endpoint_is_unavailable_and_the_caller_is_not_navigating : given.a_tenant_selection_endpoint
{
    void Establish() => _context.Request.Headers.Remove("Sec-Fetch-Dest");

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_prevent_caching() => _context.Response.Headers.CacheControl.ToString().ShouldEqual("no-store");
    [Fact] void should_respond_with_service_unavailable() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status503ServiceUnavailable);
    [Fact] void should_not_serve_an_error_page() => _errorPageProvider.DidNotReceive().WriteErrorPageAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<int>());
    [Fact] void should_not_write_a_response_body() => _context.Response.Body.Length.ShouldEqual(0);
    [Fact] void should_not_call_next() => _nextCalled.ShouldBeFalse();
    [Fact] void should_not_set_tenant_cookies() => _context.Response.Headers.SetCookie.ToString().ShouldBeEmpty();
}
