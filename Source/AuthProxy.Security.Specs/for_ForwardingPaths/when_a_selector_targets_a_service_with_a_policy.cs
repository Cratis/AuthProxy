// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_ForwardingPaths;

/// <summary>A selector cannot bypass the policy of the destination it actually selects.</summary>
/// <param name="harness">The running proxy and recording origins.</param>
[Collection(ForwardingPathSpecCollection.Name)]
public class when_a_selector_targets_a_service_with_a_policy(ForwardingPathHarness harness)
{
    [Theory]
    [InlineData("/api/other?x-cratis-microservice=reports")]
    [InlineData("/api/other?service=reports")]
    public async Task should_not_contact_the_origin(string target)
    {
        using var client = harness.CreateSecurityClient();
        using var request = ServiceRoutingHarness.Request(target);
        harness.ClearOrigins();
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        harness.AssertNoOrigins();
    }

    [Fact]
    public async Task should_forward_to_the_allow_listed_destination()
    {
        using var client = harness.CreateSecurityClient();
        using var request = ServiceRoutingHarness.Request("/api/allowed/x?x-cratis-microservice=reports");
        harness.ClearOrigins();
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        harness.AssertOnlyOrigin(harness.Reports, "/api/allowed/x");
    }

    [Theory]
    [InlineData("/api/other?x-cratis-microservice=admin", null, "/api/other")]
    [InlineData("/openapi", ServiceRoutingHarness.AdminHost, "/openapi")]
    public async Task should_not_apply_another_services_policy(string target, string? host, string expectedPath)
    {
        using var client = harness.CreateSecurityClient();
        using var request = ServiceRoutingHarness.Request(target, host, withAdminClaim: true);
        harness.ClearOrigins();
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        harness.AssertOnlyOrigin(harness.Admin, expectedPath);
    }
}
