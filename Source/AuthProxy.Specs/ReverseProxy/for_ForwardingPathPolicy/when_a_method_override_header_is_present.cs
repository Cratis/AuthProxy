// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ForwardingPathPolicy;

public class when_a_method_override_header_is_present : given.a_policy
{
    void Establish() => _service.DeniedPaths = [new() { Path = "/private" }];

    [Theory]
    [InlineData("X-HTTP-Method-Override")]
    [InlineData("X-HTTP-Method")]
    [InlineData("X-Method-Override")]
    public void should_refuse_the_request(string header) => Evaluate("/public", "POST", header).ShouldEqual(ForwardingPathRefusal.MethodOverride);
}
