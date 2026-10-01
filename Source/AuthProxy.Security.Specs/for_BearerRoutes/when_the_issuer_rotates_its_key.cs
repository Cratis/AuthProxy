// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

/// <summary>
/// A token naming the issuer's new key succeeds on its first request after the old keys were cached.
/// </summary>
public class when_the_issuer_rotates_its_key
{
    [Fact]
    public async Task should_refresh_before_retrying_the_first_rotated_token()
    {
        await using var harness = new BearerRouteHarness();
        using var client = harness.CreateBearerClient();
        using var initial = await client.SendAsync(BearerRouteHarness.WithToken(HttpMethod.Get, "/mcp/before-rotation", harness.Issuer.Token()));
        Assert.Equal(HttpStatusCode.OK, initial.StatusCode);

        harness.Issuer.RotateKey();
        using var rotated = await client.SendAsync(BearerRouteHarness.WithToken(HttpMethod.Get, "/mcp/after-rotation", harness.Issuer.Token()));
        Assert.Equal(HttpStatusCode.OK, rotated.StatusCode);
        Assert.True(harness.Origin.ReceivedAnythingFor("/mcp/after-rotation"));
        Assert.Equal(2, harness.Issuer.MetadataRequests);

        harness.Issuer.RotateKey();
        using var throttled = await client.SendAsync(BearerRouteHarness.WithToken(HttpMethod.Get, "/mcp/second-rotation", harness.Issuer.Token()));
        Assert.Equal(HttpStatusCode.Unauthorized, throttled.StatusCode);
        Assert.Equal(2, harness.Issuer.MetadataRequests);
    }

    [Fact]
    public async Task should_keep_known_keys_and_back_off_when_a_refresh_fails()
    {
        await using var harness = new BearerRouteHarness();
        using var client = harness.CreateBearerClient();
        var knownToken = harness.Issuer.Token();
        using var initial = await client.SendAsync(BearerRouteHarness.WithToken(HttpMethod.Get, "/mcp/known-key", knownToken));
        Assert.Equal(HttpStatusCode.OK, initial.StatusCode);

        harness.Issuer.RotateKey();
        harness.Issuer.MetadataUnavailable = true;
        using var unknown = await client.SendAsync(BearerRouteHarness.WithToken(HttpMethod.Get, "/mcp/unknown-key", harness.Issuer.Token()));
        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
        using var known = await client.SendAsync(BearerRouteHarness.WithToken(HttpMethod.Get, "/mcp/known-key-during-outage", knownToken));
        Assert.Equal(HttpStatusCode.OK, known.StatusCode);
        using var retry = await client.SendAsync(BearerRouteHarness.WithToken(HttpMethod.Get, "/mcp/retry-unknown-key", harness.Issuer.Token()));
        Assert.Equal(HttpStatusCode.Unauthorized, retry.StatusCode);
        Assert.Equal(2, harness.Issuer.MetadataRequests);
    }
}
