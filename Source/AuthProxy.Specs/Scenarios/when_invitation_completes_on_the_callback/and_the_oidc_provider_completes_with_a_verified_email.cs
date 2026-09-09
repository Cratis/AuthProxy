// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Scenarios.when_invitation_completes_on_the_callback;

/// <summary>
/// End-to-end OIDC scenario: a real discovery/JWKS/token/userinfo round trip - AuthProxy's own state,
/// correlation, nonce and canonical-identity validation all run for real - completes the signed two-stage
/// attested invitation protocol on the callback itself. This is the OIDC sibling of
/// <see cref="and_the_capability_survives_the_round_trip"/>, which only exercises the OAuth2 handler, and
/// proves issue #118's reason propagation reaches a genuine success outcome over OIDC, not only the
/// pre-identity guards.
/// </summary>
/// <param name="factory">The shared OIDC application factory.</param>
public class and_the_oidc_provider_completes_with_a_verified_email(OidcCallbackAuthProxyFactory factory) : IClassFixture<OidcCallbackAuthProxyFactory>, IAsyncLifetime
{
    string _invitationId;
    OidcCallbackAuthProxyFactory.ProviderSignIn _signIn;
    int _exchangeCallsDuringFlow;

    public async Task InitializeAsync()
    {
        factory.Subject = OidcCallbackAuthProxyFactory.DefaultSubject;
        factory.IdentityClaims = new Dictionary<string, string>
        {
            ["email"] = "invitee@example.com",
            ["email_verified"] = "true",
            ["acr"] = "urn:mace:incommon:iap:silver",
        };

        _invitationId = Guid.NewGuid().ToString();
        var token = TokenFixture.CreateToken(
            factory.InviteKeyPair.PrivateKey,
            additionalClaims:
            [
                new Claim("jti", _invitationId),
                new Claim(OidcCallbackAuthProxyFactory.TenantClaim, OidcCallbackAuthProxyFactory.TenantId),
                new Claim("email", "invitee@example.com"),
            ]);

        using var browser = factory.CreateBrowser();
        var exchangeCallsBefore = factory.ExchangeCallCount;
        _signIn = await factory.SignInThroughProvider(browser, $"/invite/{token}");
        _exchangeCallsDuringFlow = factory.ExchangeCallCount - exchangeCallsBefore;
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] void should_challenge_the_oidc_provider() => Assert.StartsWith($"{OidcCallbackAuthProxyFactory.Authority}/authorize", _signIn.Challenge.Headers.Location?.ToString());
    [Fact] void should_call_the_attested_completion_endpoint_once() => Assert.Equal(1, _exchangeCallsDuringFlow);
    [Fact] void should_redirect_the_callback_to_the_lobby() => Assert.Equal($"{OidcCallbackAuthProxyFactory.LobbyUrl}?invitationId={_invitationId}", _signIn.Callback.Headers.Location?.ToString());
    [Fact] void should_establish_the_session() => Assert.Contains(_signIn.CallbackCookies, cookie => cookie.StartsWith(OidcCallbackAuthProxyFactory.SessionCookieName, StringComparison.Ordinal));
}
