// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Scenarios.when_invitation_completes_on_the_callback;

/// <summary>
/// End-to-end scenario: an invitation is opened, its single provider is challenged, and the provider calls
/// back with the challenge's own capability binding intact. The invitation is exchanged on the callback
/// itself — before any redirect is answered — so no follow-up request, and no cookie round-trip, stands
/// between the sign-in and the completed invitation. The browser is signed in and sent straight to the
/// lobby, never to a second provider selection.
/// </summary>
/// <param name="factory">The shared application factory.</param>
public class and_the_capability_survives_the_round_trip(CallbackAuthProxyFactory factory) : IClassFixture<CallbackAuthProxyFactory>, IAsyncLifetime
{
    string _invitationId;
    CallbackAuthProxyFactory.ProviderSignIn _signIn;
    int _exchangeCallsDuringFlow;

    public async Task InitializeAsync()
    {
        _invitationId = Guid.NewGuid().ToString();
        var token = TokenFixture.CreateToken(
            factory.InviteKeyPair.PrivateKey,
            additionalClaims: [new Claim("jti", _invitationId)]);

        using var browser = factory.CreateBrowser();
        var exchangeCallsBefore = factory.ExchangeCallCount;
        _signIn = await factory.SignInThroughProvider(browser, $"/invite/{token}");
        _exchangeCallsDuringFlow = factory.ExchangeCallCount - exchangeCallsBefore;
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void should_challenge_the_provider_for_the_invitation() =>
        Assert.StartsWith("http://idp.test/authorize", _signIn.Challenge.Headers.Location?.ToString());

    [Fact]
    public void should_call_the_exchange_endpoint_on_the_callback() =>
        Assert.Equal(1, _exchangeCallsDuringFlow);

    [Fact]
    public void should_redirect_the_callback_to_the_lobby_with_the_invitation_id() =>
        Assert.Equal(
            $"{CallbackAuthProxyFactory.LobbyUrl}?invitationId={_invitationId}",
            _signIn.Callback.Headers.Location?.ToString());

    [Fact]
    public void should_establish_the_session()
    {
        Assert.Contains(
            _signIn.CallbackCookies,
            cookie => cookie.StartsWith(CallbackAuthProxyFactory.SessionCookieName, StringComparison.Ordinal));
    }

    [Fact]
    public void should_delete_the_pending_invitation_cookie()
    {
        _signIn.Callback.Headers.TryGetValues("Set-Cookie", out var cookies);
        Assert.Contains(
            cookies ?? [],
            cookie => cookie.StartsWith($"{Cookies.InviteToken}=;", StringComparison.Ordinal));
    }
}
