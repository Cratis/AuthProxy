// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Security.for_UpstreamRequests;

public class when_a_passthrough_route_receives_a_bearer_token(PassthroughAuthenticationHarness harness) : IClassFixture<PassthroughAuthenticationHarness>
{
    [Theory]
    [InlineData("/api/passthrough")]
    [InlineData("/API/PASSTHROUGH")]
    [InlineData("/api/passthrough/")]
    [InlineData("/api/passthrough/child")]
    [InlineData("/API/PASSTHROUGH/child")]
    public async Task should_leave_all_bearer_tokens_to_the_backend(string path)
    {
        using var client = harness.CreateBearerClient();
        foreach (var token in new[] { ClientCredentialsToken(), JwtToken(), JwtToken("backend-only"), JwtToken("backend-only", PassthroughAuthenticationHarness.BackendBearerIssuer) })
        {
            harness.Origin.Clear();
            var discoveryRequests = harness.Issuer.MetadataRequests;
            using var request = BearerRouteHarness.WithToken(HttpMethod.Get, path, token);
            using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("False", Assert.Single(response.Headers.GetValues(PassthroughAuthenticationHarness.AuthenticatedHeader)));
            Assert.Equal(string.Empty, Assert.Single(response.Headers.GetValues(PassthroughAuthenticationHarness.TenantHeader)));
            Assert.Equal("False", Assert.Single(response.Headers.GetValues(PassthroughAuthenticationHarness.ValidatedTokenHeader)));
            Assert.Equal(discoveryRequests, harness.Issuer.MetadataRequests);
            var forwarded = Assert.Single(harness.Origin.Received);
            Assert.Equal(path, forwarded.Path);
            Assert.Equal($"Bearer {token}", forwarded.Value("Authorization"));
            Assert.False(forwarded.Has(Headers.Principal));
            Assert.False(forwarded.Has(Headers.TenantId));
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task should_still_authenticate_proxy_tokens_outside_the_selected_passthrough_route(bool clientCredentials)
    {
        using var client = harness.CreateBearerClient();
        harness.Origin.Clear();
        var token = clientCredentials ? ClientCredentialsToken() : JwtToken();
        using var request = BearerRouteHarness.WithToken(HttpMethod.Get, "/api/passthrough-other", token);
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("True", Assert.Single(response.Headers.GetValues(PassthroughAuthenticationHarness.AuthenticatedHeader)));
        Assert.Equal(BearerRouteHarness.TenantId, Assert.Single(response.Headers.GetValues(PassthroughAuthenticationHarness.TenantHeader)));
        Assert.True(harness.Origin.ReceivedAnythingFor(WellKnownPaths.IdentityDetails));
    }

    [Fact]
    public async Task should_still_refuse_a_bearer_route_issuer_outside_the_selected_passthrough_route()
    {
        using var client = harness.CreateBearerClient();
        harness.Origin.Clear();
        using var request = BearerRouteHarness.WithToken(HttpMethod.Get, "/api/passthrough-other", JwtToken("backend-only", PassthroughAuthenticationHarness.BackendBearerIssuer));
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Empty(harness.Origin.Received);
    }

    string ClientCredentialsToken() => harness.Services.GetRequiredService<ClientCredentialsTokenProtector>().CreateToken(
        new ConfiguredClientCredentialsService("app", "/api", new Uri($"{harness.Origin.BaseUrl}/verify")),
        SecurityHarness.UniqueUser("passthrough"),
        BearerRouteHarness.TenantId);

    string JwtToken(string audience = BearerRouteHarness.Audience, string? issuer = null) => harness.Issuer.Token(new StubIssuer.TokenRequest
    {
        Claims = new Dictionary<string, object> { ["sub"] = SecurityHarness.UniqueUser("passthrough") },
        Audience = audience,
        Issuer = issuer,
    });
}
