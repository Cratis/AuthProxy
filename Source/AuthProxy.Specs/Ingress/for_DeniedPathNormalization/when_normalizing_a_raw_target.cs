// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Ingress.for_DeniedPathNormalization;

public class when_normalizing_a_raw_target
{
    [Theory]
    [InlineData("/internal", "/internal")]
    [InlineData("/internal/", "/internal")]
    [InlineData("/INTERNAL/CHILD", "/INTERNAL/CHILD")]
    [InlineData("/internal//child", "/internal/child")]
    [InlineData("//internal", "/internal")]
    [InlineData("/./internal", "/internal")]
    [InlineData("/public/../internal", "/internal")]
    [InlineData("/public/%2e%2E/internal", "/internal")]
    [InlineData("/%69nternal", "/internal")]
    [InlineData("/internal?destination=%2fpublic&secret=hidden", "/internal")]
    [InlineData("/public?destination=/internal", "/public")]
    [InlineData("/%C3%A9", "/é")]
    [InlineData("/a/..", "/")]
    public void should_produce_one_canonical_path(string target, string expected)
    {
        DeniedPathNormalization.TryNormalize(target, out var path).ShouldBeTrue();
        path.ShouldEqual(expected);
    }
}
