// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_ServiceRouting;

/// <summary>
/// Anonymous API paths use the same backend and stripped path as authenticated API paths.
/// </summary>
/// <param name="harness">The running proxy and its distinct backend and frontend origins.</param>
[Collection(ServiceRoutingSpecCollection.Name)]
public class when_an_anonymous_api_is_under_a_stripped_prefix(ServiceRoutingHarness harness)
{
    [Fact]
    public async Task should_forward_to_the_backend_without_a_session()
    {
        using var client = harness.CreateSecurityClient();
        harness.ClearOrigins();
        using var response = await client.GetAsync($"{ServiceRoutingHarness.ReportsPrefix}/api/health");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var forwarded = harness.Reports.LastRequestTo("/api/health");
        Assert.NotNull(forwarded);
        Assert.Equal(ServiceRoutingHarness.ReportsPrefix, forwarded.Value("X-Forwarded-Prefix"));
        Assert.False(harness.ReportsFrontend.ReceivedAnythingFor("/api/health"));
    }
}
