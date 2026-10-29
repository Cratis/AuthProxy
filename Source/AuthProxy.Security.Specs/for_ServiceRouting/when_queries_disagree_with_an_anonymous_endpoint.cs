// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_ServiceRouting;

/// <summary>
/// An anonymous endpoint remains authoritative even when queries name a privileged service.
/// </summary>
/// <param name="harness">The real proxy and recording origins.</param>
[Collection(ServiceRoutingSpecCollection.Name)]
public class when_queries_disagree_with_an_anonymous_endpoint(ServiceRoutingHarness harness)
{
    [Theory]
    [InlineData("?x-cratis-microservice=admin&service=portal")]
    [InlineData("?x-cratis-microservice=portal&service=admin")]
    public async Task should_keep_anonymous_access_and_the_declared_destination(string query)
    {
        harness.ClearOrigins();
        using var client = harness.CreateSecurityClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, ServiceRoutingHarness.ReportsPrefix + "/api/health" + query);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        using var response = await client.SendAsync(request, timeout.Token);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("origin", await response.Content.ReadAsStringAsync(timeout.Token));
        var forwarded = Assert.IsType<ForwardedRequest>(harness.Reports.LastRequestTo("/api/health"));
        Assert.Equal(query, forwarded.QueryString);
        Assert.Equal("reports", forwarded.Value(Headers.ServiceId));
        Assert.Equal("reports", forwarded.Value(Headers.LegacyServiceId));
        foreach (var other in new[] { harness.Admin, harness.Portal, harness.ReportsFrontend })
        {
            Assert.False(other.ReceivedAnythingFor("/api/health"));
        }
    }
}
