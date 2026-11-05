// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_SignedForwarding;

/// <summary>The tenant endpoint uses its own configured audience and key, not a service's settings.</summary>
/// <param name="harness">The running v1 deployment.</param>
[Collection(ForwardedIdentitySpecCollection.Name)]
public class when_the_tenant_endpoint_opts_into_signing(ForwardedIdentityHarness harness) : IAsyncLifetime
{
    ForwardedIdentityObservation _observed = null!;
    HttpStatusCode _status;
    public async ValueTask InitializeAsync()
    {
        harness.Tenants.Received.Clear();
        using var client = harness.CreateSecurityClient();
        using var request = ForwardedIdentityHarness.Session(ForwardedIdentityHarness.SignedHost, WellKnownPaths.SelectTenant + "?tenantId=11111111-1111-1111-1111-111111111111");
        using var response = await client.SendAsync(request);
        _status = response.StatusCode;
        _observed = harness.Tenants.Received.Single();
    }
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    [Fact] public void should_accept_the_selected_tenant() => Assert.Equal(HttpStatusCode.Found, _status);
    [Fact] public void should_be_accepted_by_the_tenant_verifier() => Assert.True(_observed.Verified);
    [Fact] public void should_use_the_tenant_endpoints_key() => Assert.StartsWith("v1.tenants-1.", _observed.Proof, StringComparison.Ordinal);
    [Fact] public void should_bind_the_exact_tenant_endpoint_path() => Assert.Equal("/tenants", _observed.RawTarget);
}
