// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_StickyRouting;

/// <summary>Untrusted cookie contents cannot introduce an address, destination or authority.</summary>
/// <param name="harness">The proxy and discovered origins.</param>
[Collection(StickyRoutingSpecCollection.Name)]
public class when_the_affinity_cookie_is_tampered(StickyRoutingHarness harness) : IAsyncLifetime
{
    readonly List<HttpStatusCode> _statuses = [];
    readonly List<int> _hits = [];
    readonly List<bool> _freshCookies = [];

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        foreach (var value in new[] { "dW50cnVzdGVkLWJyb3dzZXItdmFsdWU", "reporting-backend-destination-forged#0000000000000000", "http://169.254.169.254/" })
        {
            harness.ClearOrigins();
            harness.Replica.Clear();
            using var request = AccessTokenForwardingHarness.FromSession("/api/tampered", "session-one");
            request.Headers.TryAddWithoutValidation("Cookie", $".cratis-affinity-reporting={value}");
            using var response = await client.SendAsync(request);
            _statuses.Add(response.StatusCode);
            _hits.Add(harness.Backend.Received.Count + harness.Replica.Received.Count);
            _freshCookies.Add(response.Headers.TryGetValues("Set-Cookie", out var cookies)
                && cookies.Any(cookie => cookie.StartsWith(".cratis-affinity-reporting=", StringComparison.Ordinal)));
        }
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact] public void should_succeed_for_each_untrusted_value() => Assert.All(_statuses, status => Assert.Equal(HttpStatusCode.OK, status));
    [Fact] public void should_reach_exactly_one_discovered_replica_per_request() => Assert.All(_hits, hits => Assert.Equal(1, hits));
    [Fact] public void should_replace_each_forged_cookie() => Assert.All(_freshCookies, Assert.True);
}
