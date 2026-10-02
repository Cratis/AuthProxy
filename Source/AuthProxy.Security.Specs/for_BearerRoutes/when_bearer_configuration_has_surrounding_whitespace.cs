// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

/// <summary>
/// Startup validation and runtime authentication agree on trimmed tenant claims and issuer identifiers.
/// </summary>
public class when_bearer_configuration_has_surrounding_whitespace
{
    [Fact]
    public async Task should_validate_and_forward_the_original_tenant_claim()
    {
        await using var harness = new PaddedBearerRouteHarness();
        using var client = harness.CreateBearerClient();
        using var response = await client.SendAsync(BearerRouteHarness.WithToken(
            HttpMethod.Get,
            "/mcp/trimmed-configuration",
            harness.Issuer.Token(new Dictionary<string, object> { ["tenant"] = BearerRouteHarness.TenantId }, without: ["tid"])));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(BearerRouteHarness.TenantId, harness.Origin.LastRequestTo("/mcp/trimmed-configuration")?.Value(Headers.TenantId));
    }

    [Fact]
    public async Task should_not_accept_a_padded_issuer_inside_a_token()
    {
        await using var harness = new PaddedBearerRouteHarness();
        using var client = harness.CreateBearerClient();
        using var response = await client.SendAsync(BearerRouteHarness.WithToken(
            HttpMethod.Get,
            "/mcp/padded-token-issuer",
            harness.Issuer.Token(issuer: $" {harness.Issuer.Issuer} ")));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.False(harness.Origin.ReceivedAnythingFor("/mcp/padded-token-issuer"));
    }
}
