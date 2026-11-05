// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_SignedForwarding;

/// <summary>Signing refusal cannot admit identity under BestEffort or turn tenant unavailability into membership.</summary>
/// <param name="harness">The signing-refusal deployment.</param>
public class when_back_channel_signing_is_refused(RefusedBackChannelSigningHarness harness) : IClassFixture<RefusedBackChannelSigningHarness>, IAsyncLifetime
{
    HttpStatusCode _identityStatus;
    HttpStatusCode _tenantStatus;
    bool _tenantCookieIssued;

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        using var identity = ForwardedIdentityHarness.Session(ForwardedIdentityHarness.SignedHost, "/api/refused-identity");
        using var identityResponse = await client.SendAsync(identity);
        _identityStatus = identityResponse.StatusCode;
        using var tenant = ForwardedIdentityHarness.Session(ForwardedIdentityHarness.SignedHost, WellKnownPaths.SelectTenant + "?tenantId=11111111-1111-1111-1111-111111111111");
        using var tenantResponse = await client.SendAsync(tenant);
        _tenantStatus = tenantResponse.StatusCode;
        _tenantCookieIssued = tenantResponse.Headers.TryGetValues("Set-Cookie", out var cookies) && cookies.Any(cookie => cookie.StartsWith(".cratis-tenant=", StringComparison.Ordinal));
    }
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    [Fact] public void should_refuse_identity_even_under_best_effort() => Assert.Equal(HttpStatusCode.Forbidden, _identityStatus);
    [Fact] public void should_not_call_the_identity_endpoint() => Assert.Empty(harness.ApplicationOrigin.Received);
    [Fact] public void should_return_tenant_unavailability() => Assert.Equal(HttpStatusCode.ServiceUnavailable, _tenantStatus);
    [Fact] public void should_not_call_the_tenant_endpoint() => Assert.Empty(harness.Tenants.Received);
    [Fact] public void should_not_confirm_a_tenant() => Assert.False(_tenantCookieIssued);
}
