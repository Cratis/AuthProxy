// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;

namespace Cratis.AuthProxy.Security.for_FreshAuthentication;

/// <summary>Protected read paths cannot tunnel a method through a body, even with a fresh session.</summary>
/// <param name="harness">The attested proxy and recording backend.</param>
public class when_safe_reads_have_bodies(FreshAuthenticationHarness harness) : IClassFixture<FreshAuthenticationHarness>
{
    /// <summary>Provides GET and HEAD bodies using known-length and chunked framing in both forwarding flows.</summary>
    /// <returns>Protected paths, methods and framing choices.</returns>
    public static IEnumerable<TheoryDataRow<string, string, bool>> BodyRequests()
    {
        foreach (var path in new[] { "/approve", "/mcp/approve", "/v1/approve" })
        {
            foreach (var method in new[] { "GET", "HEAD" })
            {
                yield return new(path, method, false);
                yield return new(path, method, true);
            }
        }
    }

    [Theory]
    [MemberData(nameof(BodyRequests))]
    public async Task should_not_forward_a_safe_body_on_a_delete_only_path(string path, string method, bool chunked)
    {
        using var client = harness.CreateBearerClient();
        using var request = CreateRequest(new HttpMethod(method), path);
        request.Content = Body();
        request.Headers.TransferEncodingChunked = chunked;
        harness.Origin.Clear();
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(path == "/approve" ? HttpStatusCode.BadRequest : HttpStatusCode.NotFound, response.StatusCode);
        Assert.Empty(harness.Origin.Received);
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("HEAD")]
    public async Task should_refuse_a_safe_body_even_with_a_fresh_cookie(string method)
    {
        using var client = harness.CreateBearerClient();
        using var request = harness.WithSession(new HttpMethod(method), "/approve", TimeSpan.Zero);
        request.Content = Body();
        harness.Origin.Clear();
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Empty(harness.Origin.Received);
    }

    [Theory]
    [InlineData("/approve", "GET")]
    [InlineData("/approve", "HEAD")]
    [InlineData("/mcp/approve", "GET")]
    [InlineData("/mcp/approve", "HEAD")]
    [InlineData("/v1/approve", "GET")]
    [InlineData("/v1/approve", "HEAD")]
    public async Task should_preserve_bodyless_reads(string path, string method)
    {
        using var client = harness.CreateBearerClient();
        using var request = CreateRequest(new HttpMethod(method), path);
        harness.Origin.Clear();
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Single(harness.Origin.Received);
    }

    [Theory]
    [InlineData("/read", "GET")]
    [InlineData("/read", "HEAD")]
    [InlineData("/mcp/read", "GET")]
    [InlineData("/mcp/read", "HEAD")]
    public async Task should_not_restrict_bodies_outside_protected_paths(string path, string method)
    {
        using var client = harness.CreateBearerClient();
        using var request = CreateRequest(new HttpMethod(method), path);
        request.Content = Body();
        harness.Origin.Clear();
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Single(harness.Origin.Received);
    }

    [Fact]
    public async Task should_allow_a_get_with_an_explicitly_empty_body()
    {
        using var client = harness.CreateBearerClient();
        using var request = harness.WithSession(HttpMethod.Get, "/approve");
        request.Content = new ByteArrayContent([]);
        harness.Origin.Clear();
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Single(harness.Origin.Received);
    }

    static StringContent Body() => new(/*lang=json,strict*/ "{\"_method\":\"DELETE\"}", Encoding.UTF8, "application/json");

    HttpRequestMessage CreateRequest(HttpMethod method, string path) =>
        path.StartsWith("/mcp", StringComparison.Ordinal) || path.StartsWith("/v1", StringComparison.Ordinal)
            ? BearerRouteHarness.WithToken(method, path, harness.Issuer.Token())
            : harness.WithSession(method, path);
}
