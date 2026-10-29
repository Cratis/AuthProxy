// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ForwardingPathMiddleware;

public class when_a_forwarding_rule_refuses_the_selected_service : given.a_forwarding_request
{
    [Theory]
    [InlineData("GET")]
    [InlineData("HEAD")]
    public async Task should_stop_before_the_next_forwarding_stage(string method)
    {
        Select();
        _context.Request.Method = method;
        foreach (var header in new[] { "WWW-Authenticate", "Allow", "Location", "Set-Cookie" }) _context.Response.Headers[header] = "queued";
        await Invoke();
        AssertDenied();
    }

    [Fact]
    async Task should_not_change_behavior_without_a_policy()
    {
        _config.Services["app"] = new C.Service();
        Select();
        await Invoke();
        _continued.ShouldBeTrue();
    }
}
