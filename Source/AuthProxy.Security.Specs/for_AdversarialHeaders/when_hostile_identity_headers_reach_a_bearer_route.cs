// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_AdversarialHeaders;

/// <summary>
/// Bearer routes forward only token-derived identity.
/// </summary>
/// <param name="harness">The running proxy and issuer.</param>
[Collection(BearerRouteSpecCollection.Name)]
public class when_hostile_identity_headers_reach_a_bearer_route(BearerRouteHarness harness) : IAsyncLifetime
{
    const string Path = BearerRouteHarness.RoutePrefix + "/hostile";
    readonly Dictionary<HostileHeaderVariant, HttpStatusCode> _status = [];
    readonly Dictionary<HostileHeaderVariant, ForwardedRequest[]> _received = [];

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateBearerClient();
        foreach (var variant in HostileIdentityHeaders.Variants)
        {
            harness.Origin.Clear();
            using var request = BearerRouteHarness.WithToken(HttpMethod.Get, Path, harness.Issuer.Token());
            HostileIdentityHeaders.ApplyTo(request, variant);
            using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
            _status[variant] = response.StatusCode;
            _received[variant] = harness.Origin.Received.ToArray();
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
    public void should_forward_the_request(HostileHeaderVariant variant) => Assert.Equal(HttpStatusCode.OK, _status[variant]);

    [Theory]
    [InlineData(HostileHeaderVariant.Exact)]
    [InlineData(HostileHeaderVariant.Upper)]
    [InlineData(HostileHeaderVariant.Mixed)]
    [InlineData(HostileHeaderVariant.Duplicated)]
    [InlineData(HostileHeaderVariant.CaseDuplicated)]
    [InlineData(HostileHeaderVariant.Underscored)]
    public void should_not_forward_any_caller_supplied_identity_header(HostileHeaderVariant variant) => Assert.Empty(_received[variant].SelectMany(request => HostileIdentityHeaders.Leaks(request.Headers)));

    [Theory]
    [InlineData(HostileHeaderVariant.Exact)]
    [InlineData(HostileHeaderVariant.Upper)]
    [InlineData(HostileHeaderVariant.Mixed)]
    [InlineData(HostileHeaderVariant.Duplicated)]
    [InlineData(HostileHeaderVariant.CaseDuplicated)]
    [InlineData(HostileHeaderVariant.Underscored)]
    public void should_forward_the_token_identity(HostileHeaderVariant variant) => Assert.Equal(BearerRouteHarness.GitHubId, _received[variant].Last(request => request.Path == Path).Value(Headers.PrincipalId));

    [Theory]
    [InlineData(HostileHeaderVariant.Exact)]
    [InlineData(HostileHeaderVariant.Upper)]
    [InlineData(HostileHeaderVariant.Mixed)]
    [InlineData(HostileHeaderVariant.Duplicated)]
    [InlineData(HostileHeaderVariant.CaseDuplicated)]
    [InlineData(HostileHeaderVariant.Underscored)]
    public void should_forward_the_resolved_tenant(HostileHeaderVariant variant) => Assert.Equal(BearerRouteHarness.TenantId, _received[variant].Last(request => request.Path == Path).Value(Headers.TenantId));

    [Theory]
    [InlineData(HostileHeaderVariant.Exact)]
    [InlineData(HostileHeaderVariant.Upper)]
    [InlineData(HostileHeaderVariant.Mixed)]
    [InlineData(HostileHeaderVariant.Duplicated)]
    [InlineData(HostileHeaderVariant.CaseDuplicated)]
    [InlineData(HostileHeaderVariant.Underscored)]
    public void should_forward_the_token_client(HostileHeaderVariant variant) => Assert.Equal(BearerRouteHarness.ClientId, _received[variant].Last(request => request.Path == Path).Value(Headers.TokenClientId));
}
