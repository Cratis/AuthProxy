// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Identity;

namespace Cratis.AuthProxy.Security.for_ExternalTokenTenantBinding;

/// <summary>The general handler must establish a tenant before request tenancy can select a namespace.</summary>
/// <param name="harness">The general JWT deployment.</param>
[Collection(ExternalTokenBindingSpecCollection.Name)]
public class when_a_bound_token_reaches_the_proxy(ExternalTokenBindingHarness harness)
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("tenant-a ")]
    [InlineData(" tenant-a")]
    [InlineData("../tenant-a")]
    public async Task should_refuse_a_token_without_one_usable_tenant(string? tenant)
    {
        var claims = new Dictionary<string, object>();
        if (tenant is not null) claims["tid"] = tenant;
        var token = harness.Issuer.Token(new StubIssuer.TokenRequest { Claims = claims, Without = tenant is null ? ["tid"] : [] });
        await Refused(token, "/private/missing-tenant", "a.direct.example.test", HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task should_refuse_multiple_identical_tenant_values() =>
        await Refused(harness.Issuer.Token(new Dictionary<string, object> { ["tid"] = new[] { "tenant-a", "tenant-a" } }), "/private/multiple-tenants", "a.direct.example.test", HttpStatusCode.Unauthorized);

    [Theory]
    [InlineData("tenant-a", "/private/conflict", "b.direct.example.test")]
    [InlineData("tenant-a", "/private/conflict", "tenant-b.sub.example.test")]
    [InlineData("tenant-a", "/tenants/tenant-b/conflict", "localhost")]
    [InlineData("tenant-b", "/private/conflict", "localhost")]
    public async Task should_refuse_every_addressed_or_effective_tenant_conflict(string tenant, string path, string host) =>
        await Refused(harness.Issuer.Token(new Dictionary<string, object> { ["tid"] = tenant }), path, host, HttpStatusCode.Forbidden);

    [Theory]
    [InlineData("/private/accepted", "a.direct.example.test")]
    [InlineData("/tenants/tenant-a/accepted", "tenant-a.sub.example.test")]
    [InlineData("/tenant-b/not-a-configured-route", "localhost")]
    public async Task should_forward_a_matching_token_without_consulting_membership(string path, string host)
    {
        using var client = harness.CreateBearerClient();
        harness.Origin.Clear();
        using var request = BearerRouteHarness.WithToken(HttpMethod.Get, path, harness.Issuer.Token(new Dictionary<string, object> { ["tid"] = "tenant-a" }));
        request.Headers.Host = host;
        request.Headers.TryAddWithoutValidation(Headers.TenantId, "tenant-b");
        request.Headers.TryAddWithoutValidation(Headers.Principal, new ClientPrincipal
        {
            UserId = "forged-user",
            Claims = [new() { Type = "tid", Value = "tenant-b" }],
        }.ToBase64());
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Null(response.Headers.Location);
        var forwarded = Assert.Single(harness.Origin.Received);
        Assert.Equal("tenant-a", forwarded.Value(Headers.TenantId));
        Assert.Equal(path, forwarded.Path);
    }

    [Fact]
    public async Task should_not_allow_a_token_to_select_another_tenant()
    {
        var path = $"{WellKnownPaths.SelectTenant}?tenantId=tenant-b";
        await Refused(harness.Issuer.Token(new Dictionary<string, object> { ["tid"] = "tenant-a" }), path, "localhost", HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task should_replace_an_issuer_supplied_binding_marker()
    {
        var token = harness.Issuer.Token(new Dictionary<string, object>
        {
            ["tid"] = "tenant-b",
            ["Cratis.AuthProxy.ExternalTokenTenant"] = "tenant-a",
        });
        await Refused(token, "/private/forged-marker", "localhost", HttpStatusCode.Forbidden);
    }

    async Task Refused(string token, string path, string host, HttpStatusCode status)
    {
        using var client = harness.CreateBearerClient();
        harness.Origin.Clear();
        using var request = BearerRouteHarness.WithToken(HttpMethod.Get, path, token);
        request.Headers.Host = host;
        request.Headers.TryAddWithoutValidation(Headers.TenantId, "tenant-a");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(status, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.False(response.Headers.Contains("Set-Cookie"));
        Assert.False(response.Headers.Contains(Headers.Principal));
        Assert.False(response.Headers.Contains(Headers.TenantId));
        Assert.Empty(harness.Origin.Received);
    }
}
