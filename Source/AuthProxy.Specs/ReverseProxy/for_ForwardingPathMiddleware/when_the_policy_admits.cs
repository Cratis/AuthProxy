// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ForwardingPathMiddleware;

public class when_the_policy_admits : given.a_forwarding_request
{
    [Fact]
    async Task should_continue_the_selected_services_pipeline()
    {
        _context.Request.Path = "/api/public";
        Select();
        await Invoke();
        _continued.ShouldBeTrue();
    }
}
