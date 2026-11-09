// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

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
    [InlineData("/mcp/approve", "x-HtTp-MeThOd-OvErRiDe")]
    [InlineData("/mcp/approve", "x-HtTp-MeThOd")]
    [InlineData("/mcp/approve", "x-MeThOd-OvErRiDe")]
    [InlineData("/approve", "x-HtTp-MeThOd-OvErRiDe")]
    [InlineData("/approve", "x-HtTp-MeThOd")]
    [InlineData("/approve", "x-MeThOd-OvErRiDe")]
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

    /// <summary>Provides override query forms for interactive and bearer paths without forwarding-path rules.</summary>
    /// <returns>Paths and hostile query strings.</returns>
    public static IEnumerable<TheoryDataRow<string, string>> QueryOverrides()
    {
        string[] queries =
        [
            "_method=DELETE", "method=DELETE", "X-HTTP-Method-Override=DELETE", "X-HTTP-Method=DELETE", "X-Method-Override=DELETE",
            "_MeThOd=DELETE", "mEtHoD=DELETE", "x-HtTp-MeThOd-OvErRiDe=DELETE", "x-HtTp-MeThOd=DELETE", "x-MeThOd-OvErRiDe=DELETE",
            "%5Fmethod=DELETE", "m%65thod=DELETE", "X%2DHTTP%2DMethod%2DOverride=DELETE", "X%2DHTTP%2DMethod=DELETE", "X%2DMethod%2DOverride=DELETE",
            "_method=POST&_method=DELETE", "method=POST&METHOD=DELETE", "X-HTTP-Method=POST&X-HTTP-Method=DELETE",
            "_method=POST&%5FMETHOD=DELETE", "_method=", "method",
        ];
        foreach (var path in new[] { "/approve", "/mcp/approve", "/v1/approve" })
        {
            foreach (var query in queries)
            {
                yield return new(path, query);
            }
        }
    }

    [Theory]
    [MemberData(nameof(QueryOverrides))]
    public async Task should_not_forward_a_post_with_an_override_query(string path, string query)
    {
        using var client = harness.CreateBearerClient();
        using var request = path == "/approve"
            ? SecurityHarness.Authenticated(HttpMethod.Post, $"{path}?{query}", SecurityHarness.UniqueUser("freshness-query"))
            : BearerRouteHarness.WithToken(HttpMethod.Post, $"{path}?{query}", harness.Issuer.Token());
        harness.Origin.Clear();
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(path == "/approve" ? HttpStatusCode.Forbidden : HttpStatusCode.NotFound, response.StatusCode);
        Assert.Empty(harness.Origin.Received);
    }

    [Theory]
    [InlineData("/mcp/approve", "x-HtTp-MeThOd-OvErRiDe")]
    [InlineData("/mcp/approve", "x-HtTp-MeThOd")]
    [InlineData("/mcp/approve", "x-MeThOd-OvErRiDe")]
    [InlineData("/v1/approve", "x-HtTp-MeThOd-OvErRiDe")]
    [InlineData("/v1/approve", "x-HtTp-MeThOd")]
    [InlineData("/v1/approve", "x-MeThOd-OvErRiDe")]
    [InlineData("/approve", "x-HtTp-MeThOd-OvErRiDe")]
    [InlineData("/approve", "x-HtTp-MeThOd")]
    [InlineData("/approve", "x-MeThOd-OvErRiDe")]
    public async Task should_not_forward_genuine_multi_value_override_headers(string path, string header)
    {
        var token = harness.Issuer.Token();
        harness.Origin.Clear();
        var context = await harness.Server.SendAsync(
            request =>
            {
                request.Request.Method = "POST";
                request.Request.Path = path;
                request.Request.Headers[header] = new StringValues(["POST", "DELETE"]);
                Assert.Equal(2, request.Request.Headers[header].Count);
                if (path == "/approve")
                {
                    request.Request.Headers[SecurityHarness.AuthenticatedUserHeader] = SecurityHarness.UniqueUser("freshness-headers");
                }
                else
                {
                    request.Request.Headers.Authorization = $"Bearer {token}";
                }
            },
            TestContext.Current.CancellationToken);
        Assert.Equal(path == "/approve" ? StatusCodes.Status403Forbidden : StatusCodes.Status404NotFound, context.Response.StatusCode);
        Assert.Empty(harness.Origin.Received);
    }

    [Theory]
    [InlineData("/approve")]
    [InlineData("/mcp/approve")]
    [InlineData("/v1/approve")]
    public async Task should_forward_an_ordinary_query_without_changing_method_matching(string path)
    {
        using var client = harness.CreateBearerClient();
        using var request = path == "/approve"
            ? SecurityHarness.Authenticated(HttpMethod.Post, $"{path}?mode=DELETE", SecurityHarness.UniqueUser("freshness-query-control"))
            : BearerRouteHarness.WithToken(HttpMethod.Post, $"{path}?mode=DELETE", harness.Issuer.Token());
        harness.Origin.Clear();
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Single(harness.Origin.Received);
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
