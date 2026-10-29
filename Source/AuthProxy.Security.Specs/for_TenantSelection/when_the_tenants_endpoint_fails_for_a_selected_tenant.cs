// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_TenantSelection;

/// <summary>
/// A selected tenant is not forwarded when the tenants endpoint cannot confirm it.
/// </summary>
/// <param name="harness">The running proxy and its origin.</param>
[Collection(TenantSelectionSpecCollection.Name)]
public class when_the_tenants_endpoint_fails_for_a_selected_tenant(TenantSelectionHarness harness) : IAsyncLifetime
{
    HttpResponseMessage? _response;

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        harness.Origin.Clear();
        var user = SecurityHarness.UniqueUser("outage");

        // A value that has not been confirmed for this account yet needs a live answer from the tenants endpoint.
        harness.TenantsEndpointFails();
        _response = await client.SendAsync(TenantSelectionHarness.Request("/dashboard", user, $"{Cookies.Tenant}={TenantSelectionHarness.TenantA}"));
        harness.UserBelongsTo(TenantSelectionHarness.TenantA);
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact]
    public void should_answer_service_unavailable() =>
        Assert.Equal(HttpStatusCode.ServiceUnavailable, _response!.StatusCode);

    [Fact]
    public void should_not_forward_the_request_with_that_tenant() =>
        Assert.Empty(harness.RequestsForTenant(TenantSelectionHarness.TenantA));
}
