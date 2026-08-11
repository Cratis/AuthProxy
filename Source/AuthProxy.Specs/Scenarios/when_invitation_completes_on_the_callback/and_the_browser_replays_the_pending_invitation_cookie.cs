// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Scenarios.when_invitation_completes_on_the_callback;

/// <summary>
/// End-to-end scenario: the invitation completed on the callback, but the browser replays the invitation
/// URL together with a stale pending-invitation cookie — the very cookie lag that motivated completing on
/// the callback. The session carries the completion record, so nothing is exchanged again and nothing is
/// offered for selection again: the stale cookie is cleared and the browser lands at the lobby, exactly
/// where the completed invitation leads.
/// </summary>
/// <param name="factory">The shared application factory.</param>
public class and_the_browser_replays_the_pending_invitation_cookie(CallbackAuthProxyFactory factory) : IClassFixture<CallbackAuthProxyFactory>, IAsyncLifetime
{
    string _invitationId;
    HttpResponseMessage _replay;
    int _exchangeCallsDuringFlow;

    public async Task InitializeAsync()
    {
        _invitationId = Guid.NewGuid().ToString();
        var token = TokenFixture.CreateToken(
            factory.InviteKeyPair.PrivateKey,
            additionalClaims: [new Claim("jti", _invitationId)]);

        using var browser = factory.CreateBrowser();
        var exchangeCallsBefore = factory.ExchangeCallCount;
        var signIn = await factory.SignInThroughProvider(browser, $"/invite/{token}");

        using var replayRequest = new HttpRequestMessage(HttpMethod.Get, $"/invite/{token}");
        replayRequest.Headers.Add(
            "Cookie",
            string.Join("; ", signIn.CallbackCookies.Append($"{Cookies.InviteToken}={token}")));
        _replay = await browser.SendAsync(replayRequest);
        _exchangeCallsDuringFlow = factory.ExchangeCallCount - exchangeCallsBefore;
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void should_not_exchange_a_second_time() =>
        Assert.Equal(1, _exchangeCallsDuringFlow);

    [Fact]
    public void should_redirect_the_replay_to_the_lobby() =>
        Assert.Equal(
            $"{CallbackAuthProxyFactory.LobbyUrl}?invitationId={_invitationId}",
            _replay.Headers.Location?.ToString());

    [Fact]
    public void should_clear_the_stale_pending_invitation_cookie()
    {
        _replay.Headers.TryGetValues("Set-Cookie", out var cookies);
        Assert.Contains(
            cookies ?? [],
            cookie => cookie.StartsWith($"{Cookies.InviteToken}=;", StringComparison.Ordinal));
    }
}
