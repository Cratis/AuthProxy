// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

/// <summary>
/// Dot-segment tenant identifiers must not be normalized to an unrelated successful verification endpoint.
/// </summary>
public class when_the_token_tenant_is_a_dot_segment
{
    [Theory]
    [InlineData(".")]
    [InlineData("..")]
    public async Task should_refuse_without_verification_or_forwarding(string tenantId)
    {
        const string path = "/mcp/dot-tenant";
        await using var harness = new VerifyingTenantHarness();
        using var client = harness.CreateBearerClient();
        using var request = BearerRouteHarness.WithToken(HttpMethod.Get, path, harness.Issuer.Token(new Dictionary<string, object> { ["tid"] = tenantId }));
        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Empty(harness.Origin.Received);
    }

    [Fact]
    public async Task should_still_verify_and_forward_a_tenant_containing_a_dot()
    {
        const string tenantId = "tenant.one";
        const string path = "/mcp/valid-dot-tenant";
        await using var harness = new VerifyingTenantHarness();
        using var client = harness.CreateBearerClient();
        using var request = BearerRouteHarness.WithToken(HttpMethod.Get, path, harness.Issuer.Token(new Dictionary<string, object> { ["tid"] = tenantId }));
        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(harness.Origin.ReceivedAnythingFor($"/api/tenants/{tenantId}"));
        Assert.True(harness.Origin.ReceivedAnythingFor(path));
    }

    sealed class VerifyingTenantHarness : BearerRouteHarness
    {
        protected override void AddSettings(IDictionary<string, string?> settings) =>
            settings[$"{C.AuthProxy.SectionKey}:TenantVerification:UrlTemplate"] = $"{Origin.BaseUrl}/api/tenants/{{tenantId}}";
    }
}
