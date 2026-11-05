// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_SignedForwarding;

/// <summary>Redirect-disabled signed internal clients never replay an identity proof to another destination.</summary>
/// <param name="harness">The running v1 deployment.</param>
[Collection(ForwardedIdentitySpecCollection.Name)]
public class when_signed_internal_endpoints_redirect(ForwardedIdentityHarness harness) : IAsyncLifetime
{
    HttpStatusCode _identityStatus;
    HttpStatusCode _tenantStatus;
    public async ValueTask InitializeAsync()
    {
        harness.Origin.Clear();
        harness.ApplicationOrigin.Received.Clear();
        harness.Tenants.Received.Clear();
        harness.ApplicationOrigin.RedirectTo = harness.Origin.BaseUrl + "/redirected-identity";
        harness.Tenants.RedirectTo = harness.Origin.BaseUrl + "/redirected-tenants";
        using var client = harness.CreateSecurityClient();
        using var identityRequest = ForwardedIdentityHarness.Session(ForwardedIdentityHarness.SignedHost, "/api/redirect-test");
        using var identityResponse = await client.SendAsync(identityRequest);
        _identityStatus = identityResponse.StatusCode;
        using var tenantRequest = ForwardedIdentityHarness.Session(ForwardedIdentityHarness.SignedHost, WellKnownPaths.SelectTenant + "?tenantId=11111111-1111-1111-1111-111111111111");
        using var tenantResponse = await client.SendAsync(tenantRequest);
        _tenantStatus = tenantResponse.StatusCode;
    }
    public ValueTask DisposeAsync()
    {
        harness.ApplicationOrigin.RedirectTo = null;
        harness.Tenants.RedirectTo = null;
        return ValueTask.CompletedTask;
    }
    [Fact] public void should_not_follow_either_redirect() => Assert.Empty(harness.Origin.Received);
    [Fact] public void should_preserve_the_existing_identity_refusal() => Assert.Equal(HttpStatusCode.Forbidden, _identityStatus);
    [Fact] public void should_return_the_tenant_unavailable_result() => Assert.Equal(HttpStatusCode.ServiceUnavailable, _tenantStatus);
    [Fact] public void should_have_signed_the_original_identity_request() => Assert.True(harness.ApplicationOrigin.Received.Single().Verified);
    [Fact] public void should_have_signed_the_original_tenant_request() => Assert.True(harness.Tenants.Received.Single().Verified);
}
