// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_AdversarialHeaders;

/// <summary>Signed bearer forwarding retains only token-derived identity and fresh proofs.</summary>
/// <param name="harness">The running signed proxy.</param>
[Collection(ForwardedIdentitySpecCollection.Name)]
public class when_hostile_identity_headers_reach_a_signed_bearer_route(ForwardedIdentityHarness harness) : IAsyncLifetime
{
    readonly Dictionary<HostileHeaderVariant, (HttpStatusCode Status, ForwardedIdentityObservation[] Requests)> _results = [];

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        foreach (var variant in HostileIdentityHeaders.Variants)
        {
            harness.ApplicationOrigin.Received.Clear();
            using var request = BearerRouteHarness.WithToken(HttpMethod.Post, BearerRouteHarness.RoutePrefix + "/hostile", harness.Issuer.Token());
            request.Headers.Host = ForwardedIdentityHarness.SignedHost;
            HostileIdentityHeaders.ApplyTo(request, variant);
            using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
            _results[variant] = (response.StatusCode, harness.ApplicationOrigin.Received.ToArray());
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
    public void should_verify_every_identity_bearing_hop(HostileHeaderVariant variant) => Assert.All(_results[variant].Requests, request => Assert.True(request.Verified));

    [Theory]
    [InlineData(HostileHeaderVariant.Exact)]
    [InlineData(HostileHeaderVariant.Upper)]
    [InlineData(HostileHeaderVariant.Mixed)]
    [InlineData(HostileHeaderVariant.Duplicated)]
    [InlineData(HostileHeaderVariant.CaseDuplicated)]
    [InlineData(HostileHeaderVariant.Underscored)]
    public void should_emit_one_fresh_signature_per_hop(HostileHeaderVariant variant) => Assert.All(_results[variant].Requests, request => Assert.StartsWith("v1.active-1.", Assert.Single(request.Headers[Headers.ForwardedIdentitySignature]), StringComparison.Ordinal));

    [Theory]
    [InlineData(HostileHeaderVariant.Exact)]
    [InlineData(HostileHeaderVariant.Upper)]
    [InlineData(HostileHeaderVariant.Mixed)]
    [InlineData(HostileHeaderVariant.Duplicated)]
    [InlineData(HostileHeaderVariant.CaseDuplicated)]
    [InlineData(HostileHeaderVariant.Underscored)]
    public void should_forward_the_token_identity(HostileHeaderVariant variant) => Assert.Equal(BearerRouteHarness.GitHubId, Assert.Single(_results[variant].Requests, request => request.RawTarget == "/base/mcp/hostile").Headers[Headers.PrincipalId].Single());

    [Theory]
    [InlineData(HostileHeaderVariant.Exact)]
    [InlineData(HostileHeaderVariant.Upper)]
    [InlineData(HostileHeaderVariant.Mixed)]
    [InlineData(HostileHeaderVariant.Duplicated)]
    [InlineData(HostileHeaderVariant.CaseDuplicated)]
    [InlineData(HostileHeaderVariant.Underscored)]
    public void should_forward_the_token_client(HostileHeaderVariant variant) => Assert.Equal(BearerRouteHarness.ClientId, Assert.Single(_results[variant].Requests, request => request.RawTarget == "/base/mcp/hostile").Headers[Headers.TokenClientId].Single());
}
