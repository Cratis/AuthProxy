// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_CredentialBinding;

/// <summary>Addressing a tenant does not replace browser membership confirmation.</summary>
/// <param name="harness">The addressed deployment with selection enabled.</param>
[Collection(TwoTenantPersonSpecCollection.Name)]
public class when_an_unbound_browser_addresses_a_tenant(TwoTenantPersonHarness harness)
{
    [Theory]
    [InlineData(false, false, null)]
    [InlineData(false, true, null)]
    [InlineData(true, false, null)]
    [InlineData(true, true, null)]
    [InlineData(false, false, Cookies.Registration)]
    [InlineData(false, true, Cookies.Registration)]
    [InlineData(false, false, Cookies.InviteToken)]
    [InlineData(false, true, Cookies.InviteToken)]
    public async Task should_confirm_membership_before_forwarding(bool legacy, bool member, string? pending)
    {
        using var client = harness.CreateSecurityClient();
        var user = SecurityHarness.UniqueUser("addressed-browser");
        harness.UserBelongsTo(member ? TenantSelectionHarness.TenantB : TenantSelectionHarness.TenantA);
        harness.Origin.Clear();
        var cookies = new List<string>();
        if (legacy) cookies.Add($"{Cookies.Tenant}={TenantSelectionHarness.TenantA}");
        if (pending is not null) cookies.Add($"{pending}=x");
        const string path = "/api/addressed-membership";
        using var request = TenantSelectionHarness.Request(path, user, [.. cookies]);
        request.Headers.Host = "b.direct.example.test";
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Contains(harness.Origin.Received, received => received.Path == RecordingBackend.TenantsPath);
        var expected = member ? HttpStatusCode.OK : HttpStatusCode.Forbidden;
        if (member && pending == Cookies.InviteToken) expected = HttpStatusCode.Unauthorized;
        Assert.Equal(expected, response.StatusCode);
        Assert.Equal(expected == HttpStatusCode.OK, harness.Origin.ReceivedAnythingFor(path));
        if (expected != HttpStatusCode.OK)
        {
            Assert.False(response.Headers.Contains(Headers.Principal));
            Assert.False(response.Headers.Contains(Headers.TenantId));
            return;
        }

        Assert.Equal(TenantSelectionHarness.TenantB, harness.Origin.LastRequestTo(path).Value(Headers.TenantId));
        var selection = response.Headers.GetValues("Set-Cookie").First(value => value.StartsWith($"{Cookies.Tenant}=", StringComparison.Ordinal));
        selection = selection[..selection.IndexOf(';', StringComparison.Ordinal)];
        harness.Origin.Clear();
        using var repeated = TenantSelectionHarness.Request(path, user, selection);
        repeated.Headers.Host = "b.direct.example.test";
        using var continued = await client.SendAsync(repeated, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, continued.StatusCode);
        Assert.DoesNotContain(harness.Origin.Received, received => received.Path == RecordingBackend.TenantsPath);
        Assert.Equal(TenantSelectionHarness.TenantB, harness.Origin.LastRequestTo(path).Value(Headers.TenantId));
    }
}
