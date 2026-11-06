// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_AdversarialHeaders;

/// <summary>Tenant-list calls strip caller context and retain independently verifiable identity.</summary>
/// <param name="harness">The running signed proxy.</param>
[Collection(ForwardedIdentitySpecCollection.Name)]
public class when_hostile_identity_headers_reach_the_tenant_list_call(ForwardedIdentityHarness harness) : IAsyncLifetime
{
    readonly Dictionary<HostileHeaderVariant, (HttpStatusCode Status, ForwardedIdentityObservation[] Requests, ForwardedIdentityObservation[] Tenants)> _results = [];

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        foreach (var variant in HostileIdentityHeaders.Variants)
        {
            harness.ApplicationOrigin.Received.Clear();
            harness.Tenants.Received.Clear();
            using var request = ForwardedIdentityHarness.Session(ForwardedIdentityHarness.SignedHost, WellKnownPaths.SelectTenant + "?tenantId=11111111-1111-1111-1111-111111111111");
            HostileIdentityHeaders.ApplyTo(request, variant);
            using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
            _results[variant] = (response.StatusCode, harness.ApplicationOrigin.Received.Concat(harness.Tenants.Received).ToArray(), harness.Tenants.Received.ToArray());
        }
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Theory]
    [InlineData(HostileHeaderVariant.Exact)]
    [InlineData(HostileHeaderVariant.Upper)]
    [InlineData(HostileHeaderVariant.Mixed)]
    [InlineData(HostileHeaderVariant.Duplicated)]
    [InlineData(HostileHeaderVariant.CaseDuplicated)]
    [InlineData(HostileHeaderVariant.Underscored)]
    public void should_accept_the_tenant_selection(HostileHeaderVariant variant) => Assert.Equal(HttpStatusCode.Found, _results[variant].Status);

    [Theory]
    [InlineData(HostileHeaderVariant.Exact)]
    [InlineData(HostileHeaderVariant.Upper)]
    [InlineData(HostileHeaderVariant.Mixed)]
    [InlineData(HostileHeaderVariant.Duplicated)]
    [InlineData(HostileHeaderVariant.CaseDuplicated)]
    [InlineData(HostileHeaderVariant.Underscored)]
    public void should_not_forward_any_caller_supplied_identity_header(HostileHeaderVariant variant) => Assert.Empty(_results[variant].Requests.SelectMany(request => HostileIdentityHeaders.Leaks(request.Headers)));

    [Theory]
    [InlineData(HostileHeaderVariant.Exact)]
    [InlineData(HostileHeaderVariant.Upper)]
    [InlineData(HostileHeaderVariant.Mixed)]
    [InlineData(HostileHeaderVariant.Duplicated)]
    [InlineData(HostileHeaderVariant.CaseDuplicated)]
    [InlineData(HostileHeaderVariant.Underscored)]
    public void should_use_the_tenant_endpoints_independent_signature(HostileHeaderVariant variant) => Assert.True(Assert.Single(_results[variant].Tenants).Verified);

    [Theory]
    [InlineData(HostileHeaderVariant.Exact)]
    [InlineData(HostileHeaderVariant.Upper)]
    [InlineData(HostileHeaderVariant.Mixed)]
    [InlineData(HostileHeaderVariant.Duplicated)]
    [InlineData(HostileHeaderVariant.CaseDuplicated)]
    [InlineData(HostileHeaderVariant.Underscored)]
    public void should_emit_one_fresh_tenant_signature(HostileHeaderVariant variant) => Assert.StartsWith("v1.tenants-1.", Assert.Single(Assert.Single(_results[variant].Tenants).Headers[Headers.ForwardedIdentitySignature]), StringComparison.Ordinal);
}
