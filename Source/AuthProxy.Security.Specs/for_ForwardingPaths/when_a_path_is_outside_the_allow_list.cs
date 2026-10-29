// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_ForwardingPaths;

/// <summary>Reports sees only post-strip allow-listed paths, including neither traversal nor nested secrets.</summary>
/// <param name="harness">The running proxy and recording origins.</param>
[Collection(ForwardingPathSpecCollection.Name)]
public class when_a_path_is_outside_the_allow_list(ForwardingPathHarness harness)
{
    [Theory]
    [InlineData("/reports/api/other")]
    [InlineData("/reports/api/allowedX")]
    [InlineData("/reports/api/allowed/../other")]
    [InlineData("/reports/api/allowed/%2e%2e/other")]
    [InlineData("/reports/api/allowed/%252e%252e/other")]
    [InlineData("/reports/api/allowed%2f..%2fother")]
    [InlineData("/reports/api/allowed/secret")]
    [InlineData("/reports/api/allowed/SECRET/x")]
    [InlineData("/reports/index.html")]
    public async Task should_not_contact_the_origin(string target)
    {
        harness.ClearOrigins();
        var status = await harness.Raw("GET", target, "localhost", authenticated: true);
        Assert.Equal(HttpStatusCode.NotFound, status);
        harness.AssertNoOrigins();
    }

    [Theory]
    [InlineData("/reports/api/allowed/x", "/api/allowed/x", false)]
    [InlineData("/reports/", "/", true)]
    [InlineData("/reports", "/", true)]
    public async Task should_forward_the_allowed_effective_path(string target, string expectedPath, bool frontend)
    {
        harness.ClearOrigins();
        var status = await harness.Raw("GET", target, "localhost", authenticated: true);
        Assert.Equal(HttpStatusCode.OK, status);
        harness.AssertOnlyOrigin(frontend ? harness.ReportsFrontend : harness.Reports, expectedPath);
    }
}
