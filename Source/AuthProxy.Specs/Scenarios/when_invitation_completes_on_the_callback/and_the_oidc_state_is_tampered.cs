// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Scenarios.when_invitation_completes_on_the_callback;

/// <summary>
/// End-to-end OIDC scenario: the callback presents a <c language="text">state</c> value the challenge never issued. The
/// framework's own correlation validation - not any AuthProxy invitation guard - fails this closed before
/// any invitation completion code runs at all: no attestation is issued and the completion endpoint is
/// never called.
/// </summary>
/// <param name="factory">The shared OIDC application factory.</param>
public class and_the_oidc_state_is_tampered(OidcCallbackAuthProxyFactory factory) : IClassFixture<OidcCallbackAuthProxyFactory>, IAsyncLifetime
{
    HttpResponseMessage _callback;
    int _exchangeCallsDuringFlow;

    public async Task InitializeAsync()
    {
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

        var challenge = await browser.GetAsync($"/invite/{token}");
        var challengeCookies = OidcCallbackAuthProxyFactory.CookiesFrom(challenge);

        using var callbackRequest = new HttpRequestMessage(HttpMethod.Get, $"/signin-{OidcCallbackAuthProxyFactory.ProviderScheme}?code=test-code&state=not-the-issued-state");
        if (challengeCookies.Count > 0)
        {
            callbackRequest.Headers.Add("Cookie", string.Join("; ", challengeCookies));
        }

        _callback = await browser.SendAsync(callbackRequest);
        _exchangeCallsDuringFlow = factory.ExchangeCallCount - exchangeCallsBefore;
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] void should_not_call_the_completion_endpoint() => Assert.Equal(0, _exchangeCallsDuringFlow);
    [Fact] void should_fail_the_remote_round_trip_itself() => Assert.Contains("reason=remote-failure", _callback.Headers.Location?.ToString());
    [Fact] void should_not_redirect_to_lobby() => Assert.False(_callback.Headers.Location?.ToString().StartsWith(OidcCallbackAuthProxyFactory.LobbyUrl, StringComparison.Ordinal) ?? false);
    [Fact] void should_not_establish_a_session() => Assert.DoesNotContain(OidcCallbackAuthProxyFactory.CookiesFrom(_callback), cookie => cookie.StartsWith(OidcCallbackAuthProxyFactory.SessionCookieName, StringComparison.Ordinal));
}
