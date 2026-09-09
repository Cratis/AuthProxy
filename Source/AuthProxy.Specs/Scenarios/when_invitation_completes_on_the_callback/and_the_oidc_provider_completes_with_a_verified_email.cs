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
/// <remarks>
/// The completion is inspected the way the receiving backend would: the attestation is validated against the
/// configured key, issuer, audience, algorithm and lifetime - never merely decoded - and every fact on it is
/// compared to an independently known value. The transaction and challenge are compared to the ones the
/// staging call carried before the provider round trip started, so an attestation that agreed only with
/// itself could not pass.
/// </remarks>
public class and_the_oidc_provider_completes_with_a_verified_email(OidcCallbackAuthProxyFactory factory) : IClassFixture<OidcCallbackAuthProxyFactory>, IAsyncLifetime
{
    string _invitationId;
    string _capabilityHash;
    OidcCallbackAuthProxyFactory.ProviderSignIn _signIn;
    IReadOnlyDictionary<string, string> _stagedFacts;
    IReadOnlyDictionary<string, string> _attestedFacts;
    string _exchangeBody;

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
                new Claim("email", OidcCallbackAuthProxyFactory.DefaultEmail),
            ]);
        _capabilityHash = OidcCallbackAuthProxyFactory.CapabilityHashOf(token);

        using var browser = factory.CreateBrowser();
        _signIn = await factory.SignInThroughProvider(browser, $"/invite/{token}");

        _stagedFacts = await factory.ValidateAttestation(factory.StageCalls.Single().Bearer);
        var exchange = factory.ExchangeCalls.Single();
        _attestedFacts = await factory.ValidateAttestation(exchange.Bearer);
        _exchangeBody = exchange.Body;
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] void should_challenge_the_oidc_provider() => Assert.StartsWith($"{OidcCallbackAuthProxyFactory.Authority}/authorize", _signIn.Challenge.Headers.Location?.ToString());
    [Fact] void should_call_the_attested_completion_endpoint_exactly_once() => Assert.Equal(1, factory.ExchangeCallCount);
    [Fact] void should_redirect_the_callback_to_the_lobby() => Assert.Equal($"{OidcCallbackAuthProxyFactory.LobbyUrl}?invitationId={_invitationId}", _signIn.Callback.Headers.Location?.ToString());
    [Fact] void should_establish_the_session() => Assert.Contains(_signIn.CallbackCookies, cookie => cookie.StartsWith(OidcCallbackAuthProxyFactory.SessionCookieName, StringComparison.Ordinal));

    [Fact] void should_stage_before_it_completes() => Assert.Equal(InvitationAttestationClaims.StagePurpose, _stagedFacts[InvitationAttestationClaims.Purpose]);
    [Fact] void should_attest_a_completion() => Assert.Equal(InvitationAttestationClaims.CompletePurpose, _attestedFacts[InvitationAttestationClaims.Purpose]);
    [Fact] void should_attest_the_invited_tenant() => Assert.Equal(OidcCallbackAuthProxyFactory.TenantId, _attestedFacts[InvitationAttestationClaims.TenantId]);
    [Fact] void should_attest_the_invitation_it_was_issued_for() => Assert.Equal(_invitationId, _attestedFacts[InvitationAttestationClaims.InvitationId]);
    [Fact] void should_attest_the_exact_capability_presented() => Assert.Equal(_capabilityHash, _attestedFacts[InvitationAttestationClaims.CapabilityHash]);
    [Fact] void should_attest_the_staged_transaction() => Assert.Equal(_stagedFacts[InvitationAttestationClaims.InvitationTransaction], _attestedFacts[InvitationAttestationClaims.InvitationTransaction]);
    [Fact] void should_attest_the_staged_challenge() => Assert.Equal(_stagedFacts[InvitationAttestationClaims.InvitationChallenge], _attestedFacts[InvitationAttestationClaims.InvitationChallenge]);

    [Fact] void should_attest_the_configured_provider_key() => Assert.Equal(OidcCallbackAuthProxyFactory.CanonicalProviderKey, _attestedFacts[InvitationAttestationClaims.ProviderKey]);
    [Fact] void should_attest_the_framework_validated_issuer() => Assert.Equal(OidcCallbackAuthProxyFactory.Authority, _attestedFacts[InvitationAttestationClaims.ProviderIssuer]);
    [Fact] void should_attest_the_provider_subject() => Assert.Equal(OidcCallbackAuthProxyFactory.DefaultSubject, _attestedFacts[InvitationAttestationClaims.ProviderSubject]);
    [Fact] void should_attest_the_verified_provider_email() => Assert.Equal(OidcCallbackAuthProxyFactory.DefaultEmail, _attestedFacts[InvitationAttestationClaims.Email]);
    [Fact] void should_attest_that_the_email_was_verified() => Assert.Equal("True", _attestedFacts[InvitationAttestationClaims.EmailVerified], StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The assurance is AuthProxy's own statement about the protocol that authenticated this session, not an
    /// echo of whatever the provider put in its assurance claim.
    /// </summary>
    [Fact]
    public void should_attest_the_protocol_assurance_authproxy_derived()
    {
        Assert.Equal("oidc", _attestedFacts[InvitationAttestationClaims.Assurance]);
        Assert.NotEqual(OidcCallbackAuthProxyFactory.DefaultAssurance, _attestedFacts[InvitationAttestationClaims.Assurance]);
    }

    /// <summary>
    /// The body may name the transaction and nothing else - the identity facts are the attestation's to
    /// author, and a body that could name them would be a second, unsigned authority over the same question.
    /// </summary>
    [Fact]
    public void should_send_only_the_staged_transaction_in_the_body() =>
        Assert.Equal($"{{\"invitationTransaction\":\"{_stagedFacts[InvitationAttestationClaims.InvitationTransaction]}\"}}", _exchangeBody);
}
