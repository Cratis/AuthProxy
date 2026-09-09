// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Scenarios.when_invitation_completes_on_the_callback;

/// <summary>
/// End-to-end OIDC scenario: the identity provider's id_token carries a <c language="text">nonce</c> that does not match
/// the one the challenge actually generated - an id_token replayed from, or forged for, a different
/// handshake. The framework's own nonce validation fails this closed before any invitation completion code
/// runs: no attestation is issued and the completion endpoint is never called. This proves the fixture's
/// nonce handling is real validation, not a fixture that merely echoes whatever nonce it is given.
/// </summary>
/// <param name="factory">The shared OIDC application factory.</param>
public class and_the_oidc_id_token_nonce_is_wrong(OidcCallbackAuthProxyFactory factory) : IClassFixture<OidcCallbackAuthProxyFactory>, IAsyncLifetime
{
    OidcCallbackAuthProxyFactory.ProviderSignIn _signIn;
    int _exchangeCallsDuringFlow;

    public async Task InitializeAsync()
    {
        factory.Reset();
        factory.SignWithWrongNonce = true;

        var token = TokenFixture.CreateToken(
            factory.InviteKeyPair.PrivateKey,
            additionalClaims:
            [
                new Claim("jti", Guid.NewGuid().ToString()),
                new Claim(OidcCallbackAuthProxyFactory.TenantClaim, OidcCallbackAuthProxyFactory.TenantId),
                new Claim("email", "invitee@example.com"),
            ]);

        using var browser = factory.CreateBrowser();
        var exchangeCallsBefore = factory.ExchangeCallCount;
        _signIn = await factory.SignInThroughProvider(browser, $"/invite/{token}");
        _exchangeCallsDuringFlow = factory.ExchangeCallCount - exchangeCallsBefore;
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] void should_not_call_the_completion_endpoint() => Assert.Equal(0, _exchangeCallsDuringFlow);
    [Fact] void should_fail_the_remote_round_trip_itself() => Assert.Contains("reason=remote-failure", _signIn.Callback.Headers.Location?.ToString());
    [Fact] void should_not_redirect_to_lobby() => Assert.False(_signIn.Callback.Headers.Location?.ToString().StartsWith(OidcCallbackAuthProxyFactory.LobbyUrl, StringComparison.Ordinal) ?? false);
    [Fact] void should_not_establish_a_session() => Assert.DoesNotContain(_signIn.CallbackCookies, cookie => cookie.StartsWith(OidcCallbackAuthProxyFactory.SessionCookieName, StringComparison.Ordinal));
}
