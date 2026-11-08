// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_CredentialBinding;

/// <summary>Anonymous routes forward neither caller identity nor tenant context.</summary>
/// <param name="harness">The tenant-bound deployment with signed forwarding.</param>
public class when_forwarding_identity_on_anonymous_routes(AnonymousForwardingHarness harness) : IClassFixture<AnonymousForwardingHarness>
{
    [Theory]
    [InlineData("/public")]
    [InlineData("/PUBLIC")]
    [InlineData("/public/child")]
    [InlineData("/PuBlIc/child")]
    public async Task should_forward_cross_tenant_credentials_without_identity(string path)
    {
        foreach (var variant in HostileIdentityHeaders.Variants)
        {
            harness.Origin.Clear();
            using var client = harness.CreateBearerClient();
            var token = harness.Issuer.Token(claims: new Dictionary<string, object> { ["tid"] = "tenant-a" });
            using var request = BearerRouteHarness.WithToken(HttpMethod.Get, path, token);
            request.Headers.Host = "b.direct.example.test";
            HostileIdentityHeaders.ApplyTo(request, variant);
            using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var forwarded = harness.Origin.LastRequestTo(path);
            Assert.Empty(HostileIdentityHeaders.Leaks(forwarded.Headers));
            Assert.DoesNotContain(forwarded.Headers.Keys, IsIdentityHeader);
            Assert.False(forwarded.Has("Authorization"));
        }
    }

    [Theory]
    [InlineData("/public-other")]
    [InlineData("/PUBLICother")]
    [InlineData("/signin-x")]
    [InlineData("/signin-provider-one/private")]
    [InlineData("/api/private")]
    [InlineData("/declared-public")]
    [InlineData("/declared-public/child")]
    [InlineData("/register")]
    [InlineData("/.cratis/providers/child")]
    [InlineData("/.cratis/token/child")]
    [InlineData("/.cratis/select-tenant")]
    public async Task should_keep_binding_on_non_anonymous_routes(string path)
    {
        harness.Origin.Clear();
        using var client = harness.CreateBearerClient();
        var token = harness.Issuer.Token(claims: new Dictionary<string, object> { ["tid"] = "tenant-a" });
        using var request = BearerRouteHarness.WithToken(HttpMethod.Get, path, token);
        request.Headers.Host = "b.direct.example.test";
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Empty(harness.Origin.Received);
    }

    [Fact]
    public async Task should_keep_identity_and_signing_on_a_bound_non_anonymous_route()
    {
        const string path = "/api/bound";
        harness.Origin.Clear();
        using var client = harness.CreateBearerClient();
        var token = harness.Issuer.Token(claims: new Dictionary<string, object> { ["tid"] = "tenant-a" });
        using var request = BearerRouteHarness.WithToken(HttpMethod.Get, path, token);
        request.Headers.Host = "a.direct.example.test";
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var forwarded = harness.Origin.LastRequestTo(path);
        Assert.Equal("tenant-a", forwarded.Value(Headers.TenantId));
        Assert.True(forwarded.Has(Headers.Principal));
        Assert.True(forwarded.Has(Headers.ForwardedIdentitySignature));
    }

    static bool IsIdentityHeader(string name)
    {
        var normalized = name.Replace('_', '-');
        return normalized.StartsWith(Headers.PrincipalPrefix, StringComparison.OrdinalIgnoreCase)
            || normalized.StartsWith(Headers.OnBehalfPrefix, StringComparison.OrdinalIgnoreCase)
            || normalized.StartsWith(Headers.SignInCallbackPrefix, StringComparison.OrdinalIgnoreCase)
            || normalized.StartsWith("x-cratis-forwarded-identity", StringComparison.OrdinalIgnoreCase)
            || normalized.Equals(Headers.TenantId, StringComparison.OrdinalIgnoreCase)
            || normalized.Equals(Headers.LegacyTenantId, StringComparison.OrdinalIgnoreCase)
            || normalized.Equals(Headers.TokenClientId, StringComparison.OrdinalIgnoreCase)
            || normalized.Equals(Headers.TokenScope, StringComparison.OrdinalIgnoreCase);
    }
}
