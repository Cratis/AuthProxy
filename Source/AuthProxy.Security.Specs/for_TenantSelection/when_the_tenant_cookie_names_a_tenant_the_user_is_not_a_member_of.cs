// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_TenantSelection;

/// <summary>
/// A tenant named by a selected-tenant cookie is forwarded only while the signed-in user belongs to it.
/// </summary>
/// <param name="harness">The running proxy and its origin.</param>
[Collection(TenantSelectionSpecCollection.Name)]
public class when_the_tenant_cookie_names_a_tenant_the_user_is_not_a_member_of(TenantSelectionHarness harness) : IAsyncLifetime
{
    HttpResponseMessage? _response;

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        harness.Origin.Clear();
        var user = SecurityHarness.UniqueUser("member");
        var cookie = $"{Cookies.Tenant}={TenantSelectionHarness.TenantA}";

        harness.UserBelongsTo(TenantSelectionHarness.TenantB);
        harness.Origin.Clear();
        _response = await client.SendAsync(TenantSelectionHarness.Request("/dashboard", user, cookie));
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact]
    public void should_not_forward_the_request_with_that_tenant() =>
        Assert.Empty(harness.RequestsForTenant(TenantSelectionHarness.TenantA));

    [Fact]
    public void should_replay_the_request_without_the_tenant() =>
        Assert.Equal(HttpStatusCode.Found, _response!.StatusCode);
}
