// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_TenantSelection;

/// <summary>
/// The kept onboarding flow: a user with no tenants and a pending registration still reaches the registration path.
/// </summary>
/// <param name="harness">The running proxy and its origin.</param>
[Collection(TenantSelectionSpecCollection.Name)]
public class when_a_user_without_tenants_registers(TenantSelectionHarness harness) : IAsyncLifetime
{
    HttpResponseMessage? _response;

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        harness.Origin.Clear();
        var user = SecurityHarness.UniqueUser("registrant");
        harness.UserBelongsTo();
        _response = await client.SendAsync(TenantSelectionHarness.Request("/dashboard", user, $"{Cookies.Registration}=pending"));
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact]
    public void should_not_offer_a_tenant_choice() =>
        Assert.NotEqual(HttpStatusCode.Forbidden, _response!.StatusCode);
}
