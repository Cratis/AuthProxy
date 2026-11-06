// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Configuration;

namespace Cratis.AuthProxy.Security.for_CredentialBinding;

/// <summary>A fallback constrains a credential only when it is the effective tenant.</summary>
/// <param name="harness">The deployment used to configure resolution order.</param>
[Collection(TwoTenantPersonSpecCollection.Name)]
public class when_a_default_resolves_another_tenant(TwoTenantPersonHarness harness)
{
    [Theory]
    [InlineData(true, HttpStatusCode.Forbidden)]
    [InlineData(false, HttpStatusCode.OK)]
    public async Task should_compare_the_winning_tenant_with_the_credential(bool defaultFirst, HttpStatusCode expected)
    {
        await using var deployment = harness.WithWebHostBuilder(builder => builder.ConfigureAppConfiguration((_, configuration) =>
            configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                [$"{C.AuthProxy.SectionKey}:Tenants:{TenantSelectionHarness.TenantA}:SourceIdentifiers:0"] = TenantSelectionHarness.TenantA,
                [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Strategy"] = defaultFirst ? "Default" : "Claim",
                [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Options:TenantId"] = TenantSelectionHarness.TenantB,
                [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Options:ClaimType"] = "tid",
                [$"{C.AuthProxy.SectionKey}:TenantResolutions:1:Strategy"] = defaultFirst ? "Claim" : "Default",
                [$"{C.AuthProxy.SectionKey}:TenantResolutions:1:Options:TenantId"] = TenantSelectionHarness.TenantB,
                [$"{C.AuthProxy.SectionKey}:TenantResolutions:1:Options:ClaimType"] = "tid",
            })));
        using var client = deployment.CreateClient(new() { AllowAutoRedirect = false, HandleCookies = false });
        harness.Origin.Clear();
        const string path = "/api/default-binding";
        using var request = TenantSelectionHarness.Request(path, SecurityHarness.UniqueUser("default-binding"));
        request.Headers.Add(HeaderAuthenticationHandler.ClaimsHeader, $"tid={TenantSelectionHarness.TenantA}");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(expected, response.StatusCode);
        if (expected == HttpStatusCode.Forbidden)
        {
            Assert.Empty(harness.Origin.Received);
            Assert.False(response.Headers.Contains(Headers.Principal));
            Assert.False(response.Headers.Contains(Headers.TenantId));
        }
        else
        {
            Assert.Equal(TenantSelectionHarness.TenantA, harness.Origin.LastRequestTo(path).Value(Headers.TenantId));
        }
    }
}
