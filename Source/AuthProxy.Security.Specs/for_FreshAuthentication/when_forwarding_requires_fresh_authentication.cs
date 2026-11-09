// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_FreshAuthentication;

/// <summary>Neither valid bearer credentials nor method overrides may bypass a service's freshness rules.</summary>
/// <param name="harness">The running proxy, origin and issuer.</param>
public class when_forwarding_requires_fresh_authentication(FreshAuthenticationHarness harness) : IClassFixture<FreshAuthenticationHarness>
{
    [Theory]
    [InlineData("/mcp/approve")]
    [InlineData("/v1/approve")]
    public async Task should_not_forward_a_valid_bearer_on_a_freshness_limited_path(string path)
    {
        using var client = harness.CreateBearerClient();
        using var request = BearerRouteHarness.WithToken(HttpMethod.Delete, path, harness.Issuer.Token());
        harness.Origin.Clear();
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Empty(harness.Origin.Received);
    }

    [Fact]
    public async Task should_not_forward_resource_metadata_on_a_freshness_limited_path()
    {
        using var client = harness.CreateBearerClient();
        harness.Origin.Clear();
        using var response = await client.GetAsync(BearerRouteHarness.ResourceMetadataPath, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Empty(harness.Origin.Received);
    }

    [Theory]
    [InlineData("/mcp/approve", "X-HTTP-Method-Override")]
    [InlineData("/mcp/approve", "X-HTTP-Method")]
    [InlineData("/mcp/approve", "X-Method-Override")]
    [InlineData("/approve", "X-HTTP-Method-Override")]
    [InlineData("/approve", "X-HTTP-Method")]
    [InlineData("/approve", "X-Method-Override")]
    public async Task should_not_forward_a_post_that_overrides_the_method_to_delete(string path, string header)
    {
        using var client = harness.CreateBearerClient();
        using var request = path.StartsWith(BearerRouteHarness.RoutePrefix, StringComparison.Ordinal)
            ? BearerRouteHarness.WithToken(HttpMethod.Post, path, harness.Issuer.Token())
            : SecurityHarness.Authenticated(HttpMethod.Post, path, SecurityHarness.UniqueUser("freshness"));
        request.Headers.TryAddWithoutValidation(header, "DELETE");
        harness.Origin.Clear();
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(path == "/approve" ? HttpStatusCode.Forbidden : HttpStatusCode.NotFound, response.StatusCode);
        Assert.Empty(harness.Origin.Received);
    }

    [Theory]
    [InlineData("/mcp/approve")]
    [InlineData("/v1/approve")]
    public async Task should_forward_a_valid_bearer_when_the_method_does_not_require_freshness(string path)
    {
        using var client = harness.CreateBearerClient();
        using var request = BearerRouteHarness.WithToken(HttpMethod.Post, path, harness.Issuer.Token());
        harness.Origin.Clear();
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(path, Assert.Single(harness.Origin.Received).Path);
    }
}
