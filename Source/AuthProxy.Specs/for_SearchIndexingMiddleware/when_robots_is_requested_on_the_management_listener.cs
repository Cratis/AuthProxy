// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_SearchIndexingMiddleware;

public class when_robots_is_requested_on_the_management_listener : given.an_auth_proxy
{
    HttpContext _context;

    protected override IDictionary<string, string?> AdditionalSettings => new Dictionary<string, string?>
    {
        [$"{C.AuthProxy.SectionKey}:Management:Port"] = "9110"
    };

    async Task Because() => _context = await ManagementRequest("/robots.txt");

    [Fact] void should_preserve_management_isolation() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status404NotFound);
    [Fact] void should_still_add_the_header() => _context.Response.Headers["X-Robots-Tag"].ToString().ShouldEqual("noindex, nofollow");
}
