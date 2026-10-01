// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

/// <summary>
/// Known-key tokens keep working while another request awaits a slow issuer's refresh response.
/// </summary>
public class when_the_issuer_is_slow_to_refresh
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task should_answer_known_key_requests_before_the_refresh_finishes(bool unavailable)
    {
        await using var harness = new BearerRouteHarness();
        using var client = harness.CreateBearerClient();
        var knownToken = harness.Issuer.Token();
        using var initial = await client.SendAsync(BearerRouteHarness.WithToken(HttpMethod.Get, "/mcp/initial", knownToken));
        Assert.Equal(HttpStatusCode.OK, initial.StatusCode);

        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        harness.Issuer.RotateKey();
        harness.Issuer.MetadataUnavailable = unavailable;
        harness.Issuer.BeforeMetadataResponse = () =>
        {
            started.TrySetResult();
            return release.Task;
        };
        var refresh = client.SendAsync(BearerRouteHarness.WithToken(HttpMethod.Get, "/mcp/refresh", harness.Issuer.Token()));
        try
        {
            await started.Task.WaitAsync(TimeSpan.FromSeconds(5));
            using var known = await client.SendAsync(BearerRouteHarness.WithToken(HttpMethod.Get, "/mcp/known-during-refresh", knownToken))
                .WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(HttpStatusCode.OK, known.StatusCode);
            Assert.True(harness.Origin.ReceivedAnythingFor("/mcp/known-during-refresh"));
            Assert.False(refresh.IsCompleted);
        }
        finally
        {
            release.TrySetResult();
            using var refreshed = await refresh.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(unavailable ? HttpStatusCode.Unauthorized : HttpStatusCode.OK, refreshed.StatusCode);
        }

        Assert.Equal(2, harness.Issuer.MetadataRequests);
    }
}
