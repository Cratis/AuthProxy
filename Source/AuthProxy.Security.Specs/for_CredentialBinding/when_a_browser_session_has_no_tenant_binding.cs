// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_CredentialBinding;

/// <summary>
/// An authenticated browser without a tenant binding uses normal selection and membership verification.
/// </summary>
/// <param name="harness">The tenant-selection deployment.</param>
[Collection(TenantSelectionSpecCollection.Name)]
public class when_a_browser_session_has_no_tenant_binding(TenantSelectionHarness harness)
{
    [Fact]
    public async Task should_select_only_a_tenant_the_account_belongs_to()
    {
        using var client = harness.CreateSecurityClient();
        var user = SecurityHarness.UniqueUser("unbound-browser");
        harness.UserBelongsTo(TenantSelectionHarness.TenantA, TenantSelectionHarness.TenantB);
        harness.Origin.Clear();
        const string path = "/api/unbound-browser";
        using var request = TenantSelectionHarness.Request(path, user);
        request.Headers.Accept.ParseAdd("text/html");
        using var chooser = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, chooser.StatusCode);
        Assert.Contains(WellKnownPageNames.SelectTenant, await chooser.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        Assert.DoesNotContain(chooser.Headers.GetValues("Set-Cookie"), value => value.StartsWith($"{Cookies.Tenant}=", StringComparison.Ordinal));
        Assert.Contains(harness.Origin.Received, forwarded => forwarded.Path == RecordingBackend.TenantsPath);
        Assert.False(harness.Origin.ReceivedAnythingFor(path));

        using var nonmember = await client.SendAsync(
            TenantSelectionHarness.Request($"{WellKnownPaths.SelectTenant}?tenantId=another-tenant", user),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, nonmember.StatusCode);
        Assert.False(harness.Origin.ReceivedAnythingFor(path));

        var cookie = await harness.SelectTenant(client, user, TenantSelectionHarness.TenantB);
        using var continued = await client.SendAsync(TenantSelectionHarness.Request(path, user, cookie), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, continued.StatusCode);
        Assert.Equal(TenantSelectionHarness.TenantB, harness.Origin.LastRequestTo(path).Value(Headers.TenantId));
    }
}
