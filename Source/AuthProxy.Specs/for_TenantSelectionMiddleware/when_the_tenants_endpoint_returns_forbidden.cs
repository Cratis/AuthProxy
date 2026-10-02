// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware;

public class when_the_tenants_endpoint_returns_forbidden : given.a_tenant_selection_endpoint
{
    void Establish() => _endpointStatus = HttpStatusCode.Forbidden;

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_call_next_for_normal_no_tenant_handling() => _nextCalled.ShouldBeTrue();
    [Fact] void should_not_serve_an_error_page() => _errorPageProvider.DidNotReceive().WriteErrorPageAsync(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<int>());
    [Fact] void should_not_set_tenant_cookies() => _context.Response.Headers.SetCookie.ToString().ShouldBeEmpty();
}
