// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Scenarios.when_invitation_completes_on_the_callback;

/// <summary>
/// End-to-end OIDC scenario: a real discovery/JWKS/token/userinfo round trip - AuthProxy's own state,
/// correlation and nonce validated for real - answers a challenge that carries no invitation binding at
/// all. This is the OIDC sibling of
/// <see cref="and_the_capability_does_not_survive_the_round_trip"/>, which only exercises the OAuth2
/// handler: nothing is exchanged on the callback, and no downstream completion call is ever made for a
/// callback that does not answer this invitation's own challenge.
/// </summary>
/// <param name="factory">The shared OIDC application factory.</param>
public class and_the_oidc_capability_does_not_survive_the_round_trip(OidcCallbackAuthProxyFactory factory) : IClassFixture<OidcCallbackAuthProxyFactory>, IAsyncLifetime
{
    string _token;
    OidcCallbackAuthProxyFactory.ProviderSignIn _signIn;
    int _exchangeCallsDuringCallback;

    public async Task InitializeAsync()
    {
        factory.Reset();

        _token = TokenFixture.CreateToken(
            factory.InviteKeyPair.PrivateKey,
            additionalClaims: [new Claim("jti", Guid.NewGuid().ToString())]);

        using var browser = factory.CreateBrowser();
        var exchangeCallsBefore = factory.ExchangeCallCount;

        // The challenge starts from the plain login endpoint, so its state carries no invitation binding;
        // the pending invitation cookie appears on the callback only - opened in another tab meanwhile.
        _signIn = await factory.SignInThroughProvider(
            browser,
            $"/.cratis/login/{OidcCallbackAuthProxyFactory.ProviderScheme}?returnUrl=/",
            extraCallbackCookie: $"{Cookies.InviteToken}={_token}");
        _exchangeCallsDuringCallback = factory.ExchangeCallCount - exchangeCallsBefore;
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void should_challenge_the_oidc_provider() =>
        Assert.StartsWith($"{OidcCallbackAuthProxyFactory.Authority}/authorize", _signIn.Challenge.Headers.Location?.ToString());

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
    public void should_not_call_the_completion_endpoint_on_the_callback() =>
        Assert.Equal(0, _exchangeCallsDuringCallback);

    [Fact]
    public void should_establish_the_session_regardless() =>
        Assert.Contains(_signIn.CallbackCookies, cookie => cookie.StartsWith(OidcCallbackAuthProxyFactory.SessionCookieName, StringComparison.Ordinal));
}
