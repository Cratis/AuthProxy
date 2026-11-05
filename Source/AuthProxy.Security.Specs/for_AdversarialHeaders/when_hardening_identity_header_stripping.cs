// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_AdversarialHeaders;

/// <summary>
/// Known identity context is removed without changing service routing.
/// </summary>
/// <param name="harness">The running proxy.</param>
[Collection(SecuritySpecCollection.Name)]
public class when_hardening_identity_header_stripping(SecurityHarness harness) : IAsyncLifetime
{
    readonly Dictionary<HostileHeaderVariant, (HttpStatusCode Status, ForwardedRequest[] Received)> _results = [];

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        foreach (var variant in new[] { HostileHeaderVariant.Exact, HostileHeaderVariant.Underscored })
        {
            harness.Origin.Clear();
            using var request = SecurityHarness.Authenticated(HttpMethod.Get, SecurityHarness.ProtectedPath, SecurityHarness.UniqueUser("header-stripping"));
            request.Headers.Add(Headers.ServiceId, "app");
            HostileIdentityHeaders.ApplyTo(request, variant);
            using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
            _results[variant] = (response.StatusCode, harness.Origin.Received.ToArray());
        }
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Theory]
    [InlineData(HostileHeaderVariant.Exact)]
    [InlineData(HostileHeaderVariant.Underscored)]
    public void should_forward_the_request(HostileHeaderVariant variant) => Assert.Equal(HttpStatusCode.OK, _results[variant].Status);

    [Theory]
    [InlineData(HostileHeaderVariant.Exact)]
    [InlineData(HostileHeaderVariant.Underscored)]
    public void should_not_forward_caller_supplied_identity_context(HostileHeaderVariant variant) => Assert.Empty(_results[variant].Received.SelectMany(request => HostileIdentityHeaders.Leaks(request.Headers)));

    [Theory]
    [InlineData(HostileHeaderVariant.Exact)]
    [InlineData(HostileHeaderVariant.Underscored)]
    public void should_forward_the_routing_header(HostileHeaderVariant variant) => Assert.Equal("app", _results[variant].Received.Last(request => request.Path == SecurityHarness.ProtectedPath).Value(Headers.ServiceId));

    [Theory]
    [InlineData(HostileHeaderVariant.Exact)]
    [InlineData(HostileHeaderVariant.Underscored)]
    public void should_forward_the_resolved_tenant(HostileHeaderVariant variant) => Assert.Equal(SecurityHarness.TenantId, _results[variant].Received.Last(request => request.Path == SecurityHarness.ProtectedPath).Value(Headers.TenantId));
}
