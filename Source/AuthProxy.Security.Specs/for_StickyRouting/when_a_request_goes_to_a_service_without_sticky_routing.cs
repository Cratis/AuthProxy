// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_StickyRouting;

/// <summary>Enabling backend affinity does not opt the frontend into it.</summary>
/// <param name="harness">The proxy with a non-sticky frontend.</param>
[Collection(StickyRoutingSpecCollection.Name)]
public class when_a_request_goes_to_a_service_without_sticky_routing(StickyRoutingHarness harness) : IAsyncLifetime
{
    HttpStatusCode _status;
    string[] _cookies = [];

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        using var response = await client.SendAsync(AccessTokenForwardingHarness.FromSession("/dashboard", "session-one"));
        _status = response.StatusCode;
        _cookies = response.Headers.TryGetValues("Set-Cookie", out var cookies) ? [.. cookies] : [];
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact] public void should_succeed() => Assert.Equal(HttpStatusCode.OK, _status);
    [Fact] public void should_not_set_an_affinity_cookie() => Assert.DoesNotContain(_cookies, cookie => cookie.StartsWith(".cratis-affinity-", StringComparison.Ordinal));
}
