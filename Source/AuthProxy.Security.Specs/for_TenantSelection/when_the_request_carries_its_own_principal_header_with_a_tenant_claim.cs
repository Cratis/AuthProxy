// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_TenantSelection;

/// <summary>
/// A principal header sent by the caller does not name a tenant.
/// </summary>
/// <param name="harness">The running proxy and its origin.</param>
[Collection(TenantSelectionSpecCollection.Name)]
public class when_the_request_carries_its_own_principal_header_with_a_tenant_claim(TenantSelectionHarness harness) : IAsyncLifetime
{
    HttpResponseMessage? _response;

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        harness.Origin.Clear();
        var user = SecurityHarness.UniqueUser("header-principal");
        harness.UserBelongsTo(TenantSelectionHarness.TenantA, TenantSelectionHarness.TenantB);
        var request = TenantSelectionHarness.Request("/dashboard", user);
        var principal = new Cratis.AuthProxy.Identity.ClientPrincipal
        {
            Claims = [new Cratis.AuthProxy.Identity.ClientPrincipalClaim { Type = "tenant_claim", Value = TenantSelectionHarness.TenantA }]
        };
        request.Headers.TryAddWithoutValidation(Headers.Principal, principal.ToBase64());
        _response = await client.SendAsync(request);
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact]
    public void should_not_forward_the_request_with_the_tenant_from_the_header() =>
        Assert.Empty(harness.RequestsForTenant(TenantSelectionHarness.TenantA));
}
