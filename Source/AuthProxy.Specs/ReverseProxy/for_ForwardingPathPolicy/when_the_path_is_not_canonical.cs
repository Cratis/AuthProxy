// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ForwardingPathPolicy;

public class when_the_path_is_not_canonical : given.a_policy
{
    void Establish() => _service.DeniedPaths = [new() { Path = "/private" }];

    [Theory]
    [InlineData("/a%2fb")]
    [InlineData("/a\\b")]
    [InlineData("/a;b")]
    [InlineData("/a//b")]
    [InlineData("/a/../b")]
    [InlineData("/a/./b")]
    [InlineData("/a\0b")]
    [InlineData("/a?b")]
    [InlineData("/a#b")]
    public void should_refuse_the_path(string path) => Evaluate(path).ShouldEqual(ForwardingPathRefusal.NonCanonicalPath);
}
