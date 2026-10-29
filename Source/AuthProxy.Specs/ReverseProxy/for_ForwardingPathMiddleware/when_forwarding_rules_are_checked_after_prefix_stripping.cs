// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ForwardingPathMiddleware;

public class when_forwarding_rules_are_checked_after_prefix_stripping : given.a_forwarding_request
{
    [Fact]
    async Task should_check_the_origin_path()
    {
        _context.Request.Path = "/reports/api/private";
        Select(prefix: "/reports");
        await Invoke();
        AssertDenied();
        _context.Request.Path.Value.ShouldEqual("/reports/api/private");
    }
}
