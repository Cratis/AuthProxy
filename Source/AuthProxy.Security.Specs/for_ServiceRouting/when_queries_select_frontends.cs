// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_ServiceRouting;

/// <summary>
/// Query aliases retain frontend, header, host and path-prefix precedence through the real route table.
/// </summary>
/// <param name="harness">The real proxy and recording origins.</param>
[Collection(ServiceRoutingSpecCollection.Name)]
public class when_queries_select_frontends(ServiceRoutingHarness harness)
{
    [Theory]
    [InlineData("/dashboard", "?x-cratis-microservice=reports", null, "reports")]
    [InlineData("/dashboard", "?service=reports", null, "reports")]
    [InlineData("/dashboard", "?x-cratis-microservice=reports&service=admin", null, "reports")]
    [InlineData("/dashboard", "?x-cratis-microservice=unknown&service=reports", null, "reports")]
    [InlineData("/dashboard", "?x-cratis-microservice=admin&service=reports", "portal", "portal")]
    [InlineData("/reports/dashboard", "?x-cratis-microservice=admin&service=portal", "portal", "reports")]
    public async Task should_forward_only_to_the_selected_frontend(string path, string query, string? header, string service)
    {
        harness.ClearOrigins();
        using var client = harness.CreateSecurityClient();
        using var request = ServiceRoutingHarness.Request(path + query, ServiceRoutingHarness.AdminHost);
        if (header is not null)
        {
            request.Headers.TryAddWithoutValidation(Headers.ServiceId, header);
        }
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        using var response = await client.SendAsync(request, timeout.Token);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("origin", await response.Content.ReadAsStringAsync(timeout.Token));
        var target = service == "reports" ? harness.ReportsFrontend : harness.Portal;
        var forwarded = Assert.IsType<ForwardedRequest>(target.LastRequestTo("/dashboard"));
        Assert.Equal(query, forwarded.QueryString);
        Assert.Equal(service, forwarded.Value(Headers.ServiceId));
        Assert.Equal(service, forwarded.Value(Headers.LegacyServiceId));
        foreach (var other in new[] { harness.Reports, harness.ReportsFrontend, harness.Admin, harness.Portal }.Where(_ => _ != target))
        {
            Assert.False(other.ReceivedAnythingFor("/dashboard"));
            Assert.False(other.ReceivedAnythingFor(path));
        }
    }
}
