// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ForwardingPathPolicy;

public class when_the_service_strips_its_prefix : Specification
{
    [Theory]
    [InlineData("/reports", "/reports", "/")]
    [InlineData("/reports/", "/reports", "/")]
    [InlineData("/REPORTS/api", "/reports", "/api")]
    [InlineData("/reportsX/api", "/reports", "/reportsX/api")]
    [InlineData("/api", null, "/api")]
    public void should_compute_the_path_yarp_forwards(string path, string? prefix, string expected) => ForwardingPathPolicy.EffectivePath(path, prefix).Value.ShouldEqual(expected);
}
