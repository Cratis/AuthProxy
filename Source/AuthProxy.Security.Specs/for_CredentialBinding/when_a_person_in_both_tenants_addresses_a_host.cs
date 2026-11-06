// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_CredentialBinding;

/// <summary>Membership in both tenants does not authorize crossing a credential's tenant boundary.</summary>
/// <param name="harness">The two-tenant deployment.</param>
[Collection(TwoTenantPersonSpecCollection.Name)]
public class when_a_person_in_both_tenants_addresses_a_host(TwoTenantPersonHarness harness)
{
    [Theory]
    [InlineData("a.direct.example.test", HttpStatusCode.OK)]
    [InlineData("b.direct.example.test", HttpStatusCode.Forbidden)]
    public async Task should_refuse_a_conflicting_selection_before_membership_lookup(string host, HttpStatusCode expected)
    {
        harness.UserBelongsTo(TenantSelectionHarness.TenantA, TenantSelectionHarness.TenantB);
        using var client = harness.CreateClient(new() { AllowAutoRedirect = false, HandleCookies = false });
        var cookie = await harness.SelectTenant(client, "alice", TenantSelectionHarness.TenantA);
        harness.Origin.Clear();
        const string path = "/api/two-tenant-binding";
        using var request = TenantSelectionHarness.Request(path, "alice", cookie);
        request.Headers.Host = host;
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(expected, response.StatusCode);
        if (expected == HttpStatusCode.Forbidden)
        {
            Assert.Empty(harness.Origin.Received);
            Assert.Empty(harness.RequestsForTenant(TenantSelectionHarness.TenantB));
            var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            Assert.DoesNotContain(TenantSelectionHarness.TenantB, body, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(host, body, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(response.Headers, header =>
                header.Key.StartsWith(Headers.PrincipalPrefix, StringComparison.OrdinalIgnoreCase) ||
                header.Key.StartsWith(Headers.OnBehalfPrefix, StringComparison.OrdinalIgnoreCase));
            Assert.False(response.Headers.Contains(Headers.TenantId));
            Assert.False(response.Headers.Contains(Headers.LegacyTenantId));
            Assert.False(response.Headers.Contains(Headers.TokenClientId));
            Assert.False(response.Headers.Contains(Headers.TokenScope));
        }
        else
        {
            Assert.Equal(TenantSelectionHarness.TenantA, harness.Origin.LastRequestTo(path).Value(Headers.TenantId));
        }
    }
}
