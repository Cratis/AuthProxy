// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Scenarios.when_invitation_completes_on_the_callback;

/// <summary>
/// End-to-end scenario: a matching-tenant invitation already completed toward Lobby, and the browser replays the
/// invitation URL with the stale pending cookie.
/// </summary>
/// <param name="factory">The signed invitation factory with the matching-tenant destination set to Lobby.</param>
public class and_the_matching_tenant_lobby_completion_is_replayed(MatchingTenantLobbyRedirectCallbackAuthProxyFactory factory) :
    IClassFixture<MatchingTenantLobbyRedirectCallbackAuthProxyFactory>, IAsyncLifetime
{
    string _invitationId;
    HttpResponseMessage _replay;
    int _exchangeCallsDuringFlow;

    public async Task InitializeAsync()
    {
        _invitationId = Guid.NewGuid().ToString();
        var token = TokenFixture.CreateToken(
            factory.InviteKeyPair.PrivateKey,
            additionalClaims:
            [
                new Claim("jti", _invitationId),
                new Claim(CallbackAuthProxyFactory.TenantClaim, CallbackAuthProxyFactory.TenantId),
                new Claim("email", "invitee@example.com"),
            ]);

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
    public void should_exchange_only_once() =>
        Assert.Equal(1, _exchangeCallsDuringFlow);

    [Fact]
    public void should_redirect_the_replay_to_lobby_with_the_invitation_id() =>
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
