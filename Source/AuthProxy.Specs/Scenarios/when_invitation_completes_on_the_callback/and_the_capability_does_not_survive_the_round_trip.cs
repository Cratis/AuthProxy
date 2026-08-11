// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Scenarios.when_invitation_completes_on_the_callback;

/// <summary>
/// End-to-end scenario: a provider callback arrives with a pending invitation cookie but without the
/// invitation's own capability binding — the challenge was started for something else entirely. Nothing is
/// exchanged on the callback and the pending invitation is left alone; the post-login middleware remains the
/// one to answer it, and does, on the follow-up request the real session cookie authenticates.
/// </summary>
/// <param name="factory">The shared application factory.</param>
public class and_the_capability_does_not_survive_the_round_trip(CallbackAuthProxyFactory factory) : IClassFixture<CallbackAuthProxyFactory>, IAsyncLifetime
{
    string _invitationId;
    string _token;
    CallbackAuthProxyFactory.ProviderSignIn _signIn;
    HttpResponseMessage _followUp;
    int _exchangeCallsDuringCallback;
    int _exchangeCallsDuringFollowUp;

    public async Task InitializeAsync()
    {
        _invitationId = Guid.NewGuid().ToString();
        _token = TokenFixture.CreateToken(
            factory.InviteKeyPair.PrivateKey,
            additionalClaims: [new Claim("jti", _invitationId)]);

        using var browser = factory.CreateBrowser();

        // The challenge starts from the plain login endpoint, so its state carries no invitation binding;
        // the pending invitation cookie appears on the callback only - opened in another tab meanwhile.
        var exchangeCallsBefore = factory.ExchangeCallCount;
        _signIn = await factory.SignInThroughProvider(
            browser,
            $"/.cratis/login/{CallbackAuthProxyFactory.ProviderScheme}?returnUrl=/",
            extraCallbackCookie: $"{Cookies.InviteToken}={_token}");
        _exchangeCallsDuringCallback = factory.ExchangeCallCount - exchangeCallsBefore;

        using var followUpRequest = new HttpRequestMessage(HttpMethod.Get, "/");
        followUpRequest.Headers.Add(
            "Cookie",
            string.Join("; ", _signIn.CallbackCookies.Append($"{Cookies.InviteToken}={_token}")));
        _followUp = await browser.SendAsync(followUpRequest);
        _exchangeCallsDuringFollowUp = factory.ExchangeCallCount - exchangeCallsBefore - _exchangeCallsDuringCallback;
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void should_redirect_the_callback_to_its_own_return_url() =>
        Assert.Equal("/", _signIn.Callback.Headers.Location?.ToString());

    [Fact]
    public void should_leave_the_pending_invitation_in_place_on_the_callback()
    {
        _signIn.Callback.Headers.TryGetValues("Set-Cookie", out var cookies);
        Assert.DoesNotContain(
            cookies ?? [],
            cookie => cookie.StartsWith($"{Cookies.InviteToken}=;", StringComparison.Ordinal));
    }

    [Fact]
    public void should_not_exchange_on_the_callback() =>
        Assert.Equal(0, _exchangeCallsDuringCallback);

    [Fact]
    public void should_complete_the_invitation_through_the_middleware_on_the_follow_up() =>
        Assert.Equal(
            $"{CallbackAuthProxyFactory.LobbyUrl}?invitationId={_invitationId}",
            _followUp.Headers.Location?.ToString());

    [Fact]
    public void should_exchange_exactly_once_on_the_follow_up() =>
        Assert.Equal(1, _exchangeCallsDuringFollowUp);
}
