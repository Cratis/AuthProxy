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
    [InlineData("/private.")]
    [InlineData("/private./")]
    [InlineData("/a./b")]
    [InlineData("/private ")]
    [InlineData("/pri vate")]
    [InlineData("/private\t")]
    [InlineData("/private\u00a0")]
    [InlineData("/private\uff0f")]
    [InlineData("/private\uff3c")]
    [InlineData("/pr\u0131vate")]
    [InlineData("/pr\u017fvate")]
    public void should_refuse_the_path(string path) => Evaluate(path).ShouldEqual(ForwardingPathRefusal.NonCanonicalPath);
}
