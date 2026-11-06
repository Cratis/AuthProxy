// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

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
        var cookie = await harness.Select(staging);
        const string path = "/api/environment-replay";
        using var response = await production.SendAsync(TenantSelectionHarness.Request(path, "alice", cookie), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Contains(response.Headers.GetValues("Set-Cookie"), value => value.StartsWith($"{Cookies.Tenant}=", StringComparison.Ordinal));
        Assert.False(harness.Origin.ReceivedAnythingFor(path));
    }
}
