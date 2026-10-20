// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_SearchIndexingMiddleware;

public class when_the_management_listener_answers : given.an_auth_proxy
{
    HttpContext _context;

    protected override IDictionary<string, string?> AdditionalSettings => new Dictionary<string, string?>
    {
        [$"{C.AuthProxy.SectionKey}:Management:Port"] = "9110"
    };

    async Task Because() => _context = await ManagementRequest("/health/live");

    [Fact] void should_preserve_the_health_answer() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status200OK);
    [Fact] void should_add_the_header_even_before_ingress() => _context.Response.Headers["X-Robots-Tag"].ToString().ShouldEqual("noindex, nofollow");
}
