// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Scenarios.when_invitation_completes_on_the_callback;

/// <summary>
/// End-to-end OIDC scenario: a real discovery/JWKS/token/userinfo round trip answers this invitation's own
/// challenge - the capability binding survives - but the protected invitation-entry state cookie the browser
/// presents on the callback has been corrupted between staging and the callback (a tampered cookie, or one
/// that never round-tripped intact). The pre-HTTP entry-state guard fails closed with a bounded internal
/// reason and the generic invalid-link page; no attestation is issued and no downstream completion call is
/// ever made, exactly as issue #118 requires for a pre-HTTP failure.
/// </summary>
/// <param name="factory">The shared OIDC application factory.</param>
/// <remarks>
/// This is the opposite pole of the email-outcome scenarios in this folder: same 403, different page. The
/// body is asserted in both directions here too, so a regression that answered every refusal with one page
/// cannot stay green on either side.
/// </remarks>
public class and_the_oidc_entry_state_is_corrupted(OidcCallbackAuthProxyFactory factory) : IClassFixture<OidcCallbackAuthProxyFactory>, IAsyncLifetime
{
    string _invitationId;
    OidcCallbackAuthProxyFactory.ProviderSignIn _signIn;
    string _callbackBody;
    int _exchangeCallsDuringFlow;

    public async Task InitializeAsync()
    {
        factory.Reset();

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
        _signIn = await factory.SignInThroughProvider(
            browser,
            $"/invite/{token}",
            transformCallbackCookies: cookies => cookies
                .Select(cookie => cookie.StartsWith($"{Cookies.InvitationEntryState}=", StringComparison.Ordinal)
                    ? $"{Cookies.InvitationEntryState}=corrupted-not-a-real-protected-payload"
                    : cookie)
                .ToArray());
        _callbackBody = await _signIn.Callback.Content.ReadAsStringAsync();
        _exchangeCallsDuringFlow = factory.ExchangeCallCount - exchangeCallsBefore;
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void should_stage_the_signed_invitation() =>
        Assert.Contains(_signIn.ChallengeCookies, cookie => cookie.StartsWith($"{Cookies.InvitationEntryState}=", StringComparison.Ordinal));

    [Fact]
    public void should_not_call_the_completion_endpoint() =>
        Assert.Equal(0, _exchangeCallsDuringFlow);

    [Fact]
    public void should_refuse_the_completion() =>
        Assert.Equal(System.Net.HttpStatusCode.Forbidden, _signIn.Callback.StatusCode);

    [Fact]
    public void should_answer_with_the_generic_invalid_link_page() =>
        Assert.Contains("Invitation Invalid", _callbackBody, StringComparison.Ordinal);

    [Fact]
    public void should_not_answer_with_an_email_outcome_page()
    {
        Assert.DoesNotContain("Email Mismatch", _callbackBody, StringComparison.Ordinal);
        Assert.DoesNotContain("Email Unavailable", _callbackBody, StringComparison.Ordinal);
    }

    [Fact]
    public void should_not_redirect_to_lobby() =>
        Assert.Null(_signIn.Callback.Headers.Location);

    [Fact]
    public void should_still_authenticate_the_session() =>
        Assert.Contains(_signIn.CallbackCookies, cookie => cookie.StartsWith(OidcCallbackAuthProxyFactory.SessionCookieName, StringComparison.Ordinal));
}
