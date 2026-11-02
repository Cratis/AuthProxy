// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_TenantSelection;

/// <summary>
/// A selected-tenant cookie whose value was changed after it was issued is not honored.
/// </summary>
/// <param name="harness">The running proxy and its origin.</param>
[Collection(TenantSelectionSpecCollection.Name)]
public class when_the_tenant_cookie_value_was_altered(TenantSelectionHarness harness) : IAsyncLifetime
{
    HttpResponseMessage? _response;

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        var user = SecurityHarness.UniqueUser("altered");
        harness.UserBelongsTo(TenantSelectionHarness.TenantB);
        var cookie = await harness.SelectTenant(client, user, TenantSelectionHarness.TenantB);

        harness.Origin.Clear();
        _response = await client.SendAsync(TenantSelectionHarness.Request("/dashboard", user, $"{cookie}x"));
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact]
    public void should_not_forward_the_request_with_the_selected_tenant() =>
        Assert.Empty(harness.RequestsForTenant(TenantSelectionHarness.TenantB));

    [Fact]
    public void should_not_forward_the_request_with_any_tenant() =>
        Assert.DoesNotContain(harness.Origin.Received, request => request.Value(Headers.TenantId) is { Length: > 0 });

    [Fact]
    public void should_delete_the_selected_tenant_cookie() =>
        Assert.Contains(
            _response!.Headers.GetValues("Set-Cookie"),
            value => value.StartsWith($"{Cookies.Tenant}=;", StringComparison.Ordinal));
}
