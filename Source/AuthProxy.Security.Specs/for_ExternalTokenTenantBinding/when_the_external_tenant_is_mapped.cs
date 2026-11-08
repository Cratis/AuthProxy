// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_ExternalTokenTenantBinding;

/// <summary>A mapping is an exact allowlist, not a fallback for unknown tenants.</summary>
/// <param name="harness">The mapped general JWT deployment.</param>
[Collection(MappedExternalTokenBindingSpecCollection.Name)]
public class when_the_external_tenant_is_mapped(MappedExternalTokenBindingHarness harness)
{
    [Theory]
    [InlineData("external-a", HttpStatusCode.OK)]
    [InlineData("External-a", HttpStatusCode.Unauthorized)]
    [InlineData("external-a ", HttpStatusCode.Unauthorized)]
    [InlineData("tenant-a", HttpStatusCode.Unauthorized)]
    public async Task should_accept_only_the_exact_external_identifier(string external, HttpStatusCode expected)
    {
        using var client = harness.CreateBearerClient();
        harness.Origin.Clear();
        const string path = "/private/mapped-tenant";
        using var request = BearerRouteHarness.WithToken(HttpMethod.Get, path, harness.Issuer.Token(new Dictionary<string, object> { ["tid"] = external }));
        request.Headers.Host = "a.direct.example.test";
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(expected, response.StatusCode);
        Assert.Null(response.Headers.Location);
        if (expected == HttpStatusCode.OK)
        {
            Assert.Equal("tenant-a", Assert.Single(harness.Origin.Received).Value(Headers.TenantId));
        }
        else
        {
            Assert.Empty(harness.Origin.Received);
        }
    }
}
