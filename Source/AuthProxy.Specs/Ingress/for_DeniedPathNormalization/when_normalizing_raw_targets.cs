// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Ingress.for_DeniedPathNormalization;

public class when_normalizing_raw_targets
{
    [Theory]
    [InlineData("/internal%2fa/../x", "/internal/x")]
    [InlineData("/a//../internal/x", "/internal/x")]
    [InlineData("/a%2f../internal/x", "/internal/x")]
    [InlineData("/%69nternal%5cx", "/internal/x")]
    [InlineData("/internal%252Fx", "/internal/x")]
    [InlineData("/internal%255cx", "/internal/x")]
    [InlineData("/a/%252e%252e/internal/x", "/internal/x")]
    [InlineData("/a/.%252E/public/x", "/public/x")]
    [InlineData("/files/report%252Epdf", "/files/report%2Epdf")]
    [InlineData("/a/../public/x", "/public/x")]
    [InlineData("/public?next=/internal#ignored", "/public")]
    [InlineData("/public#fragment/../internal", "/public")]
    [InlineData("/public%3Fname%23part", "/public?name#part")]
    [InlineData("/x/%E2%82%AC", "/x/€")]
    [InlineData("/x/%25", "/x/%")]
    [InlineData("/x/a+b", "/x/a+b")]
    [InlineData("http://localhost/internal%2fa/../x?ignored", "/internal/x")]
    [InlineData("https://localhost:8443/a//../internal/x", "/internal/x")]
    [InlineData("http://[::1]:8080/internal%252fx", "/internal/x")]
    [InlineData("http://localhost?next=/internal", "/")]
    [InlineData("http://localhost", "/")]
    [InlineData("//internal/x", "/internal/x")]
    [InlineData("/shared/internal%2fa/../x", "/shared/internal/x")]
    public void should_decode_once_before_resolving_separators_and_dot_segments(string target, string expected)
    {
        DeniedPathNormalization.TryNormalizeRawTarget(target, out var normalized).ShouldBeTrue();
        normalized.ShouldEqual(expected);
    }
}
