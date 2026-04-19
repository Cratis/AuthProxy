// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Scenarios.when_invitation_link_is_used;

/// <summary>
/// End-to-end scenario: once a <c>.cratis-identity</c> cookie is present the identity details
/// provider must not be called again on subsequent requests.
/// </summary>
/// <param name="factory">The shared application factory.</param>
public class and_identity_cookie_prevents_repeated_endpoint_calls(AuthProxyFactory factory)
    : IClassFixture<AuthProxyFactory>, IAsyncLifetime
{
    public async Task InitializeAsync()
    {
        // First request: no identity cookie → resolver should call the endpoint and set the cookie.
        using var firstClient = factory.CreateTestClient(authenticated: true);
        var firstResponse = await firstClient.GetAsync("/");

        // Extract the identity cookie value from the response Set-Cookie headers.
        var identityCookieValue = firstResponse.Headers
            .GetValues("Set-Cookie")
            .Select(h => h.Split(';')[0])
            .Where(pair => pair.StartsWith(Cookies.Identity + "=", StringComparison.OrdinalIgnoreCase))
            .Select(pair => pair[(Cookies.Identity.Length + 1)..])
            .FirstOrDefault();

        // Second request: carry the identity cookie → resolver should skip the endpoint.
        using var secondClient = factory.CreateTestClient(authenticated: true);
        if (!string.IsNullOrEmpty(identityCookieValue))
            secondClient.DefaultRequestHeaders.Add("Cookie", $"{Cookies.Identity}={identityCookieValue}");

        await secondClient.GetAsync("/");
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void should_call_the_identity_endpoint_exactly_once() =>
        Assert.Equal(1, factory.IdentityCallCount);
}
