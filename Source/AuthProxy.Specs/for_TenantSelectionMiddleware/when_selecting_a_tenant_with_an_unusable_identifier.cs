// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware;

public class when_selecting_a_tenant_with_an_unusable_identifier : given.a_tenant_selection_endpoint
{
    void Establish()
    {
        _endpointStatus = HttpStatusCode.OK;
        _endpointBody = """[{"id":"a/b","name":"Path like"}]""";
        _context.Request.Path = WellKnownPaths.SelectTenant;
        _context.Request.QueryString = new QueryString("?tenantId=a%2Fb");
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_reject_the_selection() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status400BadRequest);
    [Fact] void should_not_set_the_selected_tenant_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldNotContain(Cookies.Tenant);
    [Fact] void should_not_call_the_tenants_endpoint() => _endpointCalls.ShouldEqual(0);
}
