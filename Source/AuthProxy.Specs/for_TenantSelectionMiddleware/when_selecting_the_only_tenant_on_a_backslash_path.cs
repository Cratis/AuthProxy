// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware;

public class when_selecting_the_only_tenant_on_a_backslash_path : given.a_tenant_selection_endpoint
{
    void Establish()
    {
        _endpointStatus = HttpStatusCode.OK;
        _endpointBody = """[{"id":"tenant-a","name":"Tenant A"}]""";
        _context.Request.Path = @"/\other.example/";
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_preserve_the_encoded_path() => _context.Response.Headers.Location.ToString().ShouldEqual("/%5Cother.example/");
    [Fact] void should_redirect() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status302Found);
}
