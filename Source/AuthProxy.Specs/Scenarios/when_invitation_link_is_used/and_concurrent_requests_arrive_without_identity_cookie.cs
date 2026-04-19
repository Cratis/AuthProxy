// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Scenarios.when_invitation_link_is_used;

/// <summary>
/// End-to-end scenario: multiple simultaneous authenticated requests that all arrive without the
/// <c>.cratis-identity</c> cookie must only trigger a single call to the identity details provider.
/// Without caching, every concurrent request would invoke the endpoint, causing a thundering-herd
/// effect on the initial page load after the invite exchange.
/// </summary>
/// <param name="factory">The shared application factory.</param>
public class and_concurrent_requests_arrive_without_identity_cookie(AuthProxyFactory factory)
    : IClassFixture<AuthProxyFactory>, IAsyncLifetime
{
    const int ConcurrentRequestCount = 5;

    public async Task InitializeAsync()
    {
        using var client = factory.CreateTestClient(authenticated: true);

        var tasks = Enumerable
            .Range(0, ConcurrentRequestCount)
            .Select(_ => client.GetAsync("/"))
            .ToList();

        await Task.WhenAll(tasks);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void should_call_the_identity_endpoint_only_once() =>
        Assert.Equal(1, factory.IdentityCallCount);
}
