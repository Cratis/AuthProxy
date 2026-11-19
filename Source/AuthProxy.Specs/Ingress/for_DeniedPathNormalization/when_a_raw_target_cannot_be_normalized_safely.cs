// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Ingress.for_DeniedPathNormalization;

public class when_a_raw_target_cannot_be_normalized_safely
{
    [Theory]
    [InlineData("/..")]
    [InlineData("/a/%252e%252e/../public/x")]
    [InlineData("/%252e%252e/public/x")]
    [InlineData("/x/%")]
    [InlineData("/x/%2")]
    [InlineData("/x/%GG")]
    [InlineData("/x/%C0%AE")]
    [InlineData("/x/%E2%82")]
    [InlineData("/x/%FF")]
    [InlineData("/x/%00")]
    [InlineData("/x/%0D%0A")]
    [InlineData("*")]
    [InlineData("localhost:443")]
    [InlineData("ftp://localhost/internal/x")]
    [InlineData("http:///internal/x")]
    [InlineData("http://localhost\\internal/x")]
    [InlineData("relative/path")]
    [InlineData("")]
    public void should_report_failure_without_an_alternative_path(string target)
    {
        DeniedPathNormalization.TryNormalizeRawTarget(target, out var normalized).ShouldBeFalse();
        normalized.ShouldEqual(string.Empty);
    }
}
