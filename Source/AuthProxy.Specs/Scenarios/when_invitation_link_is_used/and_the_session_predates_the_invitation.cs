// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Scenarios.when_invitation_link_is_used;

/// <summary>
/// End-to-end scenario: the browser carries a pending invite cookie and a session that was established
/// before the invitation was ever opened. Nothing is exchanged, nothing is redirected to the lobby, and the
/// pending invitation survives the request so the person can still complete it with the provider they
/// choose.
/// </summary>
/// <param name="factory">The shared application factory.</param>
public class and_the_session_predates_the_invitation(AuthProxyFactory factory) : IClassFixture<AuthProxyFactory>, IAsyncLifetime
{
    HttpResponseMessage? _response;
    int _exchangeCallsBefore;

    public async Task InitializeAsync()
    {
        var token = TokenFixture.CreateToken(
            factory.InviteKeyPair.PrivateKey,
            additionalClaims: [new Claim("jti", Guid.NewGuid().ToString())]);

        _exchangeCallsBefore = factory.ExchangeCallCount;

        using var client = factory.CreateTestClient(
            authenticated: true,
            inviteTokenCookie: token,
            sessionEstablishedByTheInvitation: false);
        _response = await client.GetAsync("/");
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void should_not_call_the_exchange_endpoint() =>
        Assert.Equal(_exchangeCallsBefore, factory.ExchangeCallCount);

    [Fact]
    public void should_not_redirect_to_the_lobby() =>
        Assert.NotEqual(AuthProxyFactory.LobbyUrl, _response.Headers.Location?.ToString());

    [Fact]
    public void should_leave_the_pending_invitation_in_place()
    {
        _response.Headers.TryGetValues("Set-Cookie", out var cookies);
        Assert.DoesNotContain(
            cookies ?? [],
            cookie => cookie.Contains(Cookies.InviteToken, StringComparison.OrdinalIgnoreCase));
    }
}
