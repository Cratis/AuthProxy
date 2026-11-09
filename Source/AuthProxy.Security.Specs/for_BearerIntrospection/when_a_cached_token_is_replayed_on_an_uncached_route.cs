// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_BearerIntrospection;

/// <summary>
/// A cached active answer on one route cannot hide revocation from another route that disables caching,
/// even when both routes use the same introspection endpoint and client.
/// </summary>
/// <param name="harness">The routes sharing an introspection endpoint and client.</param>
public class when_a_cached_token_is_replayed_on_an_uncached_route(SameEndpointIntrospectionHarness harness)
    : IClassFixture<SameEndpointIntrospectionHarness>
{
    const string CachedPath = $"{IntrospectionHarness.CachedRoute}/tools";
    const string UncachedPath = $"{IntrospectionHarness.MarkedRoute}/tools";

    [Fact]
    public async Task should_ask_the_same_endpoint_again_and_refuse_the_revoked_token()
    {
        using var client = harness.CreateBearerClient();
        var token = harness.Issuer.Token();
        harness.Endpoint.Activate(token);
        using var primed = await Send(client, CachedPath, token);
        Assert.Equal(HttpStatusCode.OK, primed.StatusCode);

        harness.Endpoint.Revoke(token);
        using var cached = await Send(client, CachedPath, token);
        Assert.Equal(HttpStatusCode.OK, cached.StatusCode);

        harness.Origin.Clear();
        using var replayed = await Send(client, UncachedPath, token);
        Assert.Equal(HttpStatusCode.Unauthorized, replayed.StatusCode);
        Assert.Contains("invalid_token", replayed.Headers.WwwAuthenticate.ToString());
        Assert.False(harness.Origin.ReceivedAnythingFor(UncachedPath));
        Assert.Equal(2, harness.Endpoint.CallsTo(StubIntrospectionEndpoint.Path));
    }

    static async Task<HttpResponseMessage> Send(HttpClient client, string path, string token) =>
        await client.SendAsync(BearerRouteHarness.WithToken(HttpMethod.Get, path, token));
}
