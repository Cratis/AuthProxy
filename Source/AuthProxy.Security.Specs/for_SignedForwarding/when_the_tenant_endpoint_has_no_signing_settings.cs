// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_SignedForwarding;

/// <summary>A tenant endpoint without explicit settings never borrows a service signing key.</summary>
public class when_the_tenant_endpoint_has_no_signing_settings
{
    [Fact]
    public async Task should_preserve_the_unsigned_tenant_flow()
    {
        await using var harness = new UnsignedTenantForwardedIdentityHarness();
        using var client = harness.CreateSecurityClient();
        using var request = ForwardedIdentityHarness.Session(ForwardedIdentityHarness.SignedHost, WellKnownPaths.SelectTenant + "?tenantId=11111111-1111-1111-1111-111111111111");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        var observed = harness.Origin.Received.Single();
        Assert.True(observed.Has(Headers.Principal));
        Assert.False(observed.Has(Headers.ForwardedIdentitySignature));
    }
}
