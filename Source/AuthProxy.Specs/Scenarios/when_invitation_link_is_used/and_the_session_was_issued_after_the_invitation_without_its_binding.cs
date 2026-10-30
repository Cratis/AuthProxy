// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Scenarios.when_invitation_link_is_used;

/// <summary>
/// End-to-end scenario: the browser carries a pending invite cookie and a session issued after the invitation
/// was created, but the session carries no binding to the invitation's own challenge. The invitation is not
/// exchanged, not redirected to the lobby, and the browser is not bounced: the request for the invitation link
/// is answered where it lands.
/// </summary>
/// <param name="factory">The shared application factory.</param>
public class and_the_session_was_issued_after_the_invitation_without_its_binding(AuthProxyFactory factory) : IClassFixture<AuthProxyFactory>, IAsyncLifetime
{
    HttpResponseMessage? _pendingResponse;
    HttpResponseMessage? _invitationLinkResponse;
    int _exchangeCallsBefore;

    public async ValueTask InitializeAsync()
    {
        var token = TokenFixture.CreateToken(
            factory.InviteKeyPair.PrivateKey,
            additionalClaims:
            [
                new Claim("jti", Guid.NewGuid().ToString()),
                new Claim("iat", DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeSeconds().ToString()),
            ]);

        _exchangeCallsBefore = factory.ExchangeCallCount;

        using var client = factory.CreateTestClient(
            authenticated: true,
            inviteTokenCookie: token,
            sessionCarriesTheInvitationBinding: false);
        _pendingResponse = await client.GetAsync("/");
        _invitationLinkResponse = await client.GetAsync($"{WellKnownPaths.InvitePathPrefix}/{token}");
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact]
    public void should_not_call_the_exchange_endpoint() =>
        Assert.Equal(_exchangeCallsBefore, factory.ExchangeCallCount);

    [Fact]
    public void should_not_redirect_to_the_lobby() =>
        Assert.NotEqual(AuthProxyFactory.LobbyUrl, _pendingResponse.Headers.Location?.ToString());

    [Fact]
    public void should_answer_the_invitation_link_without_redirecting() =>
        Assert.Null(_invitationLinkResponse.Headers.Location);
}
