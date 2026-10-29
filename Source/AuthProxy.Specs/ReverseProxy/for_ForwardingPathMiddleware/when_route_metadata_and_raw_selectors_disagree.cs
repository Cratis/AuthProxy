// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ForwardingPathMiddleware;

public class when_route_metadata_and_raw_selectors_disagree : given.a_forwarding_request
{
    [Fact]
    async Task should_honor_the_route_that_yarp_selected()
    {
        _config.Services["other"] = new C.Service();
        _context.Request.Headers[Headers.ServiceId] = "other";
        _context.Request.QueryString = new QueryString("?service-id=other");
        _context.Request.Host = new HostString("other.example.test");
        Select();
        await Invoke();
        AssertDenied();
    }
}
