// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_AdversarialHeaders;

/// <summary>Machine routes forward only authenticated identity.</summary>
/// <param name="harness">The running machine route.</param>
[Collection(MachineRouteSpecCollection.Name)]
public class when_hostile_identity_headers_reach_a_machine_route(MachineRouteHarness harness) : IAsyncLifetime
{
    const string Path = "/api/hostile";
    readonly Dictionary<HostileHeaderVariant, (HttpStatusCode Status, ForwardedRequest[] Requests)> _results = [];

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        foreach (var variant in HostileIdentityHeaders.Variants)
        {
            harness.ClearOrigins();
            using var request = harness.Request(Path);
            HostileIdentityHeaders.ApplyTo(request, variant);
            using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
            _results[variant] = (response.StatusCode, harness.Frontend.Received.Concat(harness.Backend.Received).ToArray());
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
    public void should_forward_the_request(HostileHeaderVariant variant) => Assert.Equal(HttpStatusCode.OK, _results[variant].Status);

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
    public void should_forward_the_machine_identity(HostileHeaderVariant variant) => Assert.NotEmpty(_results[variant].Requests.Last(request => request.Path == Path).Value(Headers.PrincipalId));

    [Theory]
    [InlineData(HostileHeaderVariant.Exact)]
    [InlineData(HostileHeaderVariant.Upper)]
    [InlineData(HostileHeaderVariant.Mixed)]
    [InlineData(HostileHeaderVariant.Duplicated)]
    [InlineData(HostileHeaderVariant.CaseDuplicated)]
    [InlineData(HostileHeaderVariant.Underscored)]
    public void should_forward_the_resolved_tenant(HostileHeaderVariant variant) => Assert.Equal(AccessTokenForwardingHarness.TenantId, _results[variant].Requests.Last(request => request.Path == Path).Value(Headers.TenantId));
}
