// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_CredentialBinding;

/// <summary>A valid token cannot cross the tenant or environment boundary named by the deployment.</summary>
/// <param name="harness">The addressed bearer deployment.</param>
[Collection(AddressedBearerRouteSpecCollection.Name)]
public class when_the_address_names_another_tenant(AddressedBearerRouteHarness harness)
{
    [Theory]
    [InlineData("tenant-a", "staging", "b.direct.example.test", HttpStatusCode.Forbidden)]
    [InlineData("Tenant-A", "staging", "a.direct.example.test", HttpStatusCode.Forbidden)]
    [InlineData("tenant-a ", "staging", "a.direct.example.test", HttpStatusCode.Forbidden)]
    [InlineData("tenant-a", "production", "a.direct.example.test", HttpStatusCode.Forbidden)]
    [InlineData("tenant-a", null, "a.direct.example.test", HttpStatusCode.Forbidden)]
    [InlineData("tenant-a", "Staging", "a.direct.example.test", HttpStatusCode.Forbidden)]
    [InlineData("tenant-a", "staging ", "a.direct.example.test", HttpStatusCode.Forbidden)]
    [InlineData("tenant-a", " staging", "a.direct.example.test", HttpStatusCode.Forbidden)]
    [InlineData("tenant-a", "staging", "a.direct.example.test", HttpStatusCode.OK)]
    [InlineData("tenant-a", "staging", "unaddressed.example.test", HttpStatusCode.OK)]
    public async Task should_refuse_conflicts_without_forwarding(string tenant, string? environment, string host, HttpStatusCode expected)
    {
        using var client = harness.CreateBearerClient();
        harness.Origin.Clear();
        var path = $"/mcp/binding-{Guid.NewGuid():N}";
        var claims = new Dictionary<string, object> { ["tid"] = tenant };
        if (environment is not null) claims["env"] = environment;
        using var request = BearerRouteHarness.WithToken(HttpMethod.Get, path, harness.Issuer.Token(claims: claims));
        request.Headers.Host = host;
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(expected, response.StatusCode);
        Assert.Equal(expected == HttpStatusCode.OK, harness.Origin.ReceivedAnythingFor(path));
        if (expected == HttpStatusCode.OK)
        {
            Assert.Equal(tenant, harness.Origin.LastRequestTo(path).Value(Headers.TenantId));
        }
        else
        {
            Assert.Empty(harness.Origin.Received);
            Assert.Empty(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
            Assert.False(response.Headers.Contains(Headers.Principal));
            Assert.False(response.Headers.Contains(Headers.TenantId));
        }
    }

    [Fact]
    public async Task should_refuse_multiple_environment_values()
    {
        using var client = harness.CreateBearerClient();
        harness.Origin.Clear();
        const string path = "/mcp/multiple-environments";
        using var request = BearerRouteHarness.WithToken(HttpMethod.Get, path, harness.Issuer.Token(claims: new Dictionary<string, object> { ["tid"] = "tenant-a", ["env"] = new[] { "staging", "staging" } }));
        request.Headers.Host = "a.direct.example.test";
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Empty(harness.Origin.Received);
        Assert.Empty(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        Assert.False(response.Headers.Contains(Headers.Principal));
        Assert.False(response.Headers.Contains(Headers.TenantId));
    }

    [Fact]
    public async Task should_refuse_a_case_variant_audience()
    {
        using var client = harness.CreateBearerClient();
        harness.Origin.Clear();
        const string path = "/mcp/case-variant-audience";
        using var request = BearerRouteHarness.WithToken(HttpMethod.Get, path, harness.Issuer.Token(claims: new Dictionary<string, object> { ["tid"] = "tenant-a", ["env"] = "staging" }, audience: "DIRECT-API"));
        request.Headers.Host = "a.direct.example.test";
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Empty(harness.Origin.Received);
        Assert.Empty(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        Assert.False(response.Headers.Contains(Headers.Principal));
        Assert.False(response.Headers.Contains(Headers.TenantId));
    }
}
