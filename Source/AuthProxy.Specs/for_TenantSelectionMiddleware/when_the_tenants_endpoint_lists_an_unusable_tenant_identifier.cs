// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware;

public class when_the_tenants_endpoint_lists_an_unusable_tenant_identifier : given.a_tenant_selection_endpoint
{
    void Establish()
    {
        _endpointStatus = HttpStatusCode.OK;
        _endpointBody = """[{"id":"a/b","name":"Path like"}]""";
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_auto_select_the_tenant() => _context.Response.Headers.SetCookie.ToString().ShouldNotContain(Cookies.Tenant);
    [Fact] void should_not_redirect() => _context.Response.StatusCode.ShouldNotEqual(StatusCodes.Status302Found);
    [Fact] void should_continue_as_for_a_user_without_tenants() => _nextCalled.ShouldBeTrue();
}
