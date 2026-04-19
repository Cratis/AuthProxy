// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Scenarios.when_invitation_link_is_used;

/// <summary>
/// End-to-end scenario: an authenticated user returns with a pending invite cookie.
/// Verifies that the exchange endpoint is called, identity details are resolved,
/// the identity cookie is set, and the user is redirected to the lobby.
/// </summary>
/// <param name="factory">The shared application factory.</param>
public class and_user_accepts(AuthProxyFactory factory) : IClassFixture<AuthProxyFactory>, IAsyncLifetime
{
    HttpResponseMessage? _response;

    public async Task InitializeAsync()
    {
        // Valid invite token signed with the factory's known RSA key.
        var token = TokenFixture.CreateToken(
            factory.InviteKeyPair.PrivateKey,
            additionalClaims: [new Claim("jti", Guid.NewGuid().ToString())]);

        // Authenticated request with the pending invite cookie — triggers Phase 2.
        using var client = factory.CreateTestClient(authenticated: true, inviteTokenCookie: token);
        _response = await client.GetAsync("/");
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void should_redirect_to_lobby() =>
        Assert.Equal(System.Net.HttpStatusCode.Redirect, _response.StatusCode);

    [Fact]
    public void should_redirect_to_the_configured_lobby_url() =>
        Assert.Equal(AuthProxyFactory.LobbyUrl, _response.Headers.Location?.ToString());

    [Fact]
    public void should_call_the_exchange_endpoint() =>
        Assert.True(factory.ExchangeCallCount > 0, "Exchange endpoint was not called");

    [Fact]
    public void should_call_the_identity_details_provider() =>
        Assert.True(factory.IdentityCallCount > 0, "Identity details provider was not called");

    [Fact]
    public void should_set_the_identity_cookie()
    {
        _response.Headers.TryGetValues("Set-Cookie", out var cookies);
        Assert.True(
            cookies?.Any(c => c.StartsWith(Cookies.Identity, StringComparison.OrdinalIgnoreCase)),
            $"Expected Set-Cookie header containing '{Cookies.Identity}'");
    }

    [Fact]
    public void should_delete_the_invite_cookie()
    {
        _response.Headers.TryGetValues("Set-Cookie", out var cookies);
        Assert.True(
            cookies?.Any(c => c.Contains(Cookies.InviteToken, StringComparison.OrdinalIgnoreCase)),
            $"Expected Set-Cookie header containing '{Cookies.InviteToken}'");
    }
}
