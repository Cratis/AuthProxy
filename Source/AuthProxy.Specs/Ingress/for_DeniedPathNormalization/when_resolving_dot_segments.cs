// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Ingress.for_DeniedPathNormalization;

public class when_resolving_dot_segments
{
    [Theory]
    [InlineData("/a%2f../internal/x", "/internal/x")]
    [InlineData("/a%2F..%2Finternal/x", "/internal/x")]
    [InlineData("/a%5C..%5cinternal/x", "/internal/x")]
    [InlineData("/a\\..\\internal\\x", "/internal/x")]
    [InlineData("/./internal/x", "/internal/x")]
    [InlineData("/a/b/../../internal/x", "/internal/x")]
    [InlineData("/a//../internal/x", "/internal/x")]
    [InlineData("/a/../public/x", "/public/x")]
    [InlineData("/internal-not/x", "/internal-not/x")]
    [InlineData("/a/..", "/")]
    [InlineData("/a/../", "/")]
    [InlineData("/.", "/")]
    [InlineData("/a/b/..", "/a/")]
    [InlineData("/a/.", "/a/")]
    [InlineData("/a/", "/a/")]
    [InlineData("/a/.../..name", "/a/.../..name")]
    [InlineData("", "")]
    public void should_resolve_dot_segments_after_mapping_and_collapsing_separators(string path, string expected)
    {
        DeniedPathNormalization.TryNormalize(path, out var normalized).ShouldBeTrue();
        normalized.ShouldEqual(expected);
    }
}
