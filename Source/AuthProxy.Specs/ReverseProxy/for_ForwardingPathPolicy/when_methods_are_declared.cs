// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ForwardingPathPolicy;

public class when_methods_are_declared : given.a_policy
{
    void Establish()
    {
        _service.ForwardedPaths = [new() { Path = "/api", Methods = ["get"] }];
        _service.DeniedPaths = [new() { Path = "/api/private", Methods = ["GET"] }];
    }

    [Theory]
    [InlineData("/api", "GET", ForwardingPathRefusal.None)]
    [InlineData("/api", "head", ForwardingPathRefusal.None)]
    [InlineData("/api", "OPTIONS", ForwardingPathRefusal.NotAllowed)]
    [InlineData("/api", "CUSTOM", ForwardingPathRefusal.NotAllowed)]
    [InlineData("/api/private", "GET", ForwardingPathRefusal.Denied)]
    [InlineData("/api/private", "HEAD", ForwardingPathRefusal.Denied)]
    public void should_apply_method_scope(string path, string method, ForwardingPathRefusal expected) => Evaluate(path, method).ShouldEqual(expected);
}
