// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;

namespace Cratis.AuthProxy.Security.for_CredentialBinding;

/// <summary>Route-addressed membership is confirmed per tenant without a host-wide binding cookie.</summary>
/// <param name="harness">The deployment and authoritative membership endpoint.</param>
[Collection(TwoTenantPersonSpecCollection.Name)]
public class when_a_browser_addresses_tenants_by_route(TwoTenantPersonHarness harness)
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task should_confirm_each_addressed_tenant_without_binding_the_shared_host(bool belongsToBoth)
    {
        await using var deployment = Configure();
        using var client = deployment.CreateClient(new() { AllowAutoRedirect = false, HandleCookies = true });
        var user = SecurityHarness.UniqueUser("route-membership");
        harness.UserBelongsTo(belongsToBoth ? [TenantSelectionHarness.TenantA, TenantSelectionHarness.TenantB] : [TenantSelectionHarness.TenantA]);
        const string pathA = "/a/api/route-membership";
        const string pathB = "/b/api/route-membership";
        harness.Origin.Clear();
        using var first = await client.SendAsync(TenantSelectionHarness.Request(pathA, user), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(TenantSelectionHarness.TenantA, harness.Origin.LastRequestTo(pathA).Value(Headers.TenantId));
        Assert.Contains(harness.Origin.Received, request => request.Path == RecordingBackend.TenantsPath);
        Assert.DoesNotContain(SessionCookieHarness.SetCookies(first), cookie => cookie.StartsWith($"{Cookies.Tenant}=", StringComparison.Ordinal));

        harness.Origin.Clear();
        using var second = await client.SendAsync(TenantSelectionHarness.Request(pathB, user), TestContext.Current.CancellationToken);
        Assert.Contains(harness.Origin.Received, request => request.Path == RecordingBackend.TenantsPath);
        Assert.Equal(belongsToBoth ? HttpStatusCode.OK : HttpStatusCode.Forbidden, second.StatusCode);
        Assert.Equal(belongsToBoth, harness.Origin.ReceivedAnythingFor(pathB));
        if (!belongsToBoth)
        {
            Assert.All(harness.Origin.Received, request => Assert.Equal(RecordingBackend.TenantsPath, request.Path));
            Assert.False(second.Headers.Contains(Headers.Principal));
            Assert.False(second.Headers.Contains(Headers.TenantId));
            return;
        }

        Assert.Equal(TenantSelectionHarness.TenantB, harness.Origin.LastRequestTo(pathB).Value(Headers.TenantId));
        Assert.DoesNotContain(SessionCookieHarness.SetCookies(second), cookie => cookie.StartsWith($"{Cookies.Tenant}=", StringComparison.Ordinal));
        harness.Origin.Clear();
        foreach (var path in new[] { pathA, pathB })
        {
            using var repeated = await client.SendAsync(TenantSelectionHarness.Request(path, user), TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, repeated.StatusCode);
            Assert.DoesNotContain(SessionCookieHarness.SetCookies(repeated), cookie => cookie.StartsWith($"{Cookies.Tenant}=", StringComparison.Ordinal));
        }

        Assert.DoesNotContain(harness.Origin.Received, request => request.Path == RecordingBackend.TenantsPath);
    }

    WebApplicationFactory<Program> Configure() => harness.WithWebHostBuilder(builder =>
        builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.AuthProxy.SectionKey}:Tenants:{TenantSelectionHarness.TenantA}:SourceIdentifiers:0"] = "a",
            [$"{C.AuthProxy.SectionKey}:Tenants:{TenantSelectionHarness.TenantB}:SourceIdentifiers:0"] = "b",
            [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Strategy"] = "Route",
            [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Options:Pattern"] = "^/(?<sourceIdentifier>a|b)(?:/|$)",
        })));
}
