// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Identity;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Cratis.AuthProxy.Security.for_CredentialBinding;

/// <summary>A selection from staging cannot authorize a production request, even with shared keys.</summary>
/// <param name="harness">The two environments.</param>
[Collection(EnvironmentBindingSpecCollection.Name)]
public class when_replaying_a_selection_in_another_environment(EnvironmentBindingHarness harness)
{
    [Fact]
    public async Task should_reconfirm_instead_of_forwarding()
    {
        var options = new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false };
        using var staging = harness.Staging.CreateClient(options);
        using var production = harness.Production.CreateClient(options);
        harness.UserBelongsTo(TenantSelectionHarness.TenantA);
        var cookie = await harness.Select(staging);
        harness.UserBelongsTo(TenantSelectionHarness.TenantB);
        harness.Origin.Clear();
        const string path = "/api/environment-replay";
        using var response = await production.SendAsync(TenantSelectionHarness.Request(path, "alice", cookie), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Equal(path, response.Headers.Location?.OriginalString);
        Assert.Empty(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        Assert.False(harness.Origin.ReceivedAnythingFor(path));
        Assert.Contains(harness.Origin.Received, request => request.Path == RecordingBackend.TenantsPath);
        Assert.All(harness.Origin.Received, request =>
        {
            Assert.NotEqual(TenantSelectionHarness.TenantA, request.Value(Headers.TenantId));
            Assert.NotEqual(TenantSelectionHarness.TenantA, request.Value(Headers.LegacyTenantId));
            if (request.Has(Headers.Principal))
            {
                Assert.True(ClientPrincipal.TryFromBase64(request.Value(Headers.Principal), out var principal));
                Assert.DoesNotContain(principal!.Claims, claim => claim.Value == TenantSelectionHarness.TenantA);
            }
        });

        var replacement = response.Headers.GetValues("Set-Cookie")
            .Last(value => value.StartsWith($"{Cookies.Tenant}=", StringComparison.Ordinal));
        var replacementCookie = replacement[..replacement.IndexOf(';', StringComparison.Ordinal)];
        using var continued = await production.SendAsync(TenantSelectionHarness.Request(path, "alice", replacementCookie), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, continued.StatusCode);
        Assert.Equal(TenantSelectionHarness.TenantB, harness.Origin.LastRequestTo(path).Value(Headers.TenantId));
    }
}
