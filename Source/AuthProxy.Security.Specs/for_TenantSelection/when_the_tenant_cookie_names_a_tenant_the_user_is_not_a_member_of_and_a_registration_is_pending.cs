// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_TenantSelection;

/// <summary>
/// A pending registration does not let a selected tenant through unconfirmed.
/// </summary>
/// <param name="harness">The running proxy and its origin.</param>
[Collection(TenantSelectionSpecCollection.Name)]
public class when_the_tenant_cookie_names_a_tenant_the_user_is_not_a_member_of_and_a_registration_is_pending(TenantSelectionHarness harness) : IAsyncLifetime
{
    HttpResponseMessage? _response;

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        harness.Origin.Clear();
        var user = SecurityHarness.UniqueUser("registering");
        var cookie = $"{Cookies.Tenant}={TenantSelectionHarness.TenantA}";

        harness.UserBelongsTo(TenantSelectionHarness.TenantB);
        harness.Origin.Clear();
        _response = await client.SendAsync(TenantSelectionHarness.Request("/dashboard", user, cookie, $"{Cookies.Registration}=pending"));
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact]
    public void should_not_forward_the_request_with_that_tenant() =>
        Assert.Empty(harness.RequestsForTenant(TenantSelectionHarness.TenantA));
}
