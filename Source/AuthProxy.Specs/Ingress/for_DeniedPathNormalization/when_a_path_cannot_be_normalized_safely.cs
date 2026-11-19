// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Ingress.for_DeniedPathNormalization;

public class when_a_path_cannot_be_normalized_safely
{
    [Theory]
    [InlineData("/..")]
    [InlineData("/../internal/x")]
    [InlineData("/a/../../public/x")]
    [InlineData("/a%2f..%2f..%2fpublic/x")]
    [InlineData("/a/%2e%2e/internal/x")]
    [InlineData("/a/.%2E/internal/x")]
    [InlineData("/a/%2E./internal/x")]
    [InlineData("/public/%2ename")]
    [InlineData("relative/path")]
    public void should_report_failure_without_an_alternative_path(string path)
    {
        DeniedPathNormalization.TryNormalize(path, out var normalized).ShouldBeFalse();
        normalized.ShouldEqual(string.Empty);
    }
}
