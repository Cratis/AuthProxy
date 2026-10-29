// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_TenantSelection;

/// <summary>
/// The kept flow: a member selects a tenant and the next request is forwarded with it.
/// </summary>
/// <param name="harness">The running proxy and its origin.</param>
[Collection(TenantSelectionSpecCollection.Name)]
public class when_a_member_selects_a_tenant_and_continues(TenantSelectionHarness harness) : IAsyncLifetime
{
    ForwardedRequest? _forwarded;

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        harness.Origin.Clear();
        var user = SecurityHarness.UniqueUser("member-flow");
        harness.UserBelongsTo(TenantSelectionHarness.TenantA, TenantSelectionHarness.TenantB);
        var cookie = await harness.SelectTenant(client, user, TenantSelectionHarness.TenantB);

        harness.Origin.Clear();
        await client.SendAsync(TenantSelectionHarness.Request("/dashboard", user, cookie));
        _forwarded = harness.Origin.LastRequestTo("/dashboard");
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact]
    public void should_forward_the_request_with_the_selected_tenant() =>
        Assert.Equal(TenantSelectionHarness.TenantB, _forwarded!.Value(Headers.TenantId));
}
