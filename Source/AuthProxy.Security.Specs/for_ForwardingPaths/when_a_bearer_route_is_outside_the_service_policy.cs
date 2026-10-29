// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_ForwardingPaths;

/// <summary>A valid token does not exempt a bearer route or its metadata from the service policy.</summary>
/// <param name="harness">The running proxy, origin and issuer.</param>
[Collection(ForwardingPathBearerRouteSpecCollection.Name)]
public class when_a_bearer_route_is_outside_the_service_policy(ForwardingPathBearerRouteHarness harness)
{
    [Theory]
    [InlineData("/mcp/admin/x")]
    [InlineData("/v1/x")]
    public async Task should_not_contact_the_origin(string target)
    {
        using var client = harness.CreateBearerClient();
        using var request = BearerRouteHarness.WithToken(HttpMethod.Get, target, harness.Issuer.Token());
        harness.Origin.Clear();
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Empty(harness.Origin.Received);
    }

    [Fact]
    public async Task should_forward_allowed_tools_with_a_valid_token()
    {
        using var client = harness.CreateBearerClient();
        using var request = BearerRouteHarness.WithToken(HttpMethod.Get, "/mcp/tools", harness.Issuer.Token());
        harness.Origin.Clear();
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("/mcp/tools", Assert.Single(harness.Origin.Received).Path);
    }

    [Fact]
    public async Task should_forward_allowed_resource_metadata_without_a_token()
    {
        using var client = harness.CreateBearerClient();
        harness.Origin.Clear();
        using var response = await client.GetAsync(BearerRouteHarness.ResourceMetadataPath, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(BearerRouteHarness.ResourceMetadataPath, Assert.Single(harness.Origin.Received).Path);
    }
}
