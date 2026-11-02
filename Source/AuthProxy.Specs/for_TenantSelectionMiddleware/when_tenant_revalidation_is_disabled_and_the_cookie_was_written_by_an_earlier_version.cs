// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware;

public class when_tenant_revalidation_is_disabled_and_the_cookie_was_written_by_an_earlier_version : given.a_tenant_selection_endpoint
{
    void Establish()
    {
        _authProxyConfig.Session = new C.Session { TenantRevalidationInterval = TimeSpan.Zero };
        _endpointStatus = null;
        given.signed_selected_tenant_cookies.SeedLegacy(_context, "tenant-a");
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_ask_the_tenant_endpoint_once() => _endpointCalls.ShouldEqual(1);
    [Fact] void should_not_forward_the_request() => _nextCalled.ShouldBeFalse();
    [Fact] void should_answer_service_unavailable() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status503ServiceUnavailable);

}
