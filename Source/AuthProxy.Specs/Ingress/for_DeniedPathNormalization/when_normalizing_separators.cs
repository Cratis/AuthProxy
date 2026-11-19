// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Ingress.for_DeniedPathNormalization;

public class when_normalizing_separators
{
    [Theory]
    [InlineData("/internal", "/internal")]
    [InlineData("/internal/", "/internal/")]
    [InlineData("//internal///child", "/internal/child")]
    [InlineData("/internal%2fchild", "/internal/child")]
    [InlineData("/internal%2Fchild", "/internal/child")]
    [InlineData("/internal%5cchild", "/internal/child")]
    [InlineData("/internal%5Cchild", "/internal/child")]
    [InlineData("\\internal\\child", "/internal/child")]
    [InlineData("/%2f%5C\\internal//child", "/internal/child")]
    [InlineData("/internal//../secret", "/internal/../secret")]
    public void should_only_map_and_collapse_separators(string path, string expected) =>
        DeniedPathNormalization.NormalizeSeparators(path).ShouldEqual(expected);
}
