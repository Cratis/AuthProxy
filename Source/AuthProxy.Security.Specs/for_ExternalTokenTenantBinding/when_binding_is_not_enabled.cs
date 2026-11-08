// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_ExternalTokenTenantBinding;

/// <summary>Existing general JWT deployments keep their legacy tenancy behavior.</summary>
/// <param name="harness">The deployment with no binding setting.</param>
[Collection(LegacyExternalTokenSpecCollection.Name)]
public class when_binding_is_not_enabled(LegacyExternalTokenHarness harness)
{
    [Theory]
    [InlineData(null)]
    [InlineData("tenant-b")]
    public async Task should_continue_forwarding_without_a_credential_tenant_constraint(string? tenant)
    {
        using var client = harness.CreateBearerClient();
        harness.Origin.Clear();
        var claims = new Dictionary<string, object>();
        if (tenant is not null) claims["tid"] = tenant;
        var token = harness.Issuer.Token(claims, without: tenant is null ? ["tid"] : []);
        using var request = BearerRouteHarness.WithToken(HttpMethod.Get, "/private/legacy", token);
        request.Headers.Host = "a.direct.example.test";
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("tenant-a", Assert.Single(harness.Origin.Received).Value(Headers.TenantId));
    }
}
