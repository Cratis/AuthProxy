// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_SignInNotificationSigner.given;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.SignIns.for_SignInNotificationSigner.when_issuing_an_envelope;

/// <summary>
/// Pins every one of the six facts the envelope binds. Each assertion names one fact, so a binding that stops
/// being written fails on its own rather than hiding behind "the token still verifies".
/// </summary>
public class and_the_verifier_uses_the_published_contract : a_sign_in_notification_signer
{
    bool _issued;
    string _envelope;
    JsonWebToken _token;
    TokenValidationResult _validation;

    async Task Because()
    {
        _issued = _signer.TryIssue(HttpMethod.Post, Target, Body, out _envelope);
        _token = Read(_envelope);
        _validation = await Validate(_envelope);
    }

    [Fact] void should_issue_the_envelope() => _issued.ShouldBeTrue();
    [Fact] void should_report_signing_as_enabled() => _signer.IsEnabled.ShouldBeTrue();
    [Fact] void should_verify_against_the_pinned_public_key() => _validation.IsValid.ShouldBeTrue();
    [Fact] void should_name_the_signing_key() => _token.Kid.ShouldEqual(KeyId);
    [Fact] void should_name_the_published_signing_algorithm() => _token.Alg.ShouldEqual("RS256");
    [Fact] void should_bind_provenance_to_the_configured_issuer() => _token.Issuer.ShouldEqual(Issuer);
    [Fact] void should_bind_the_audience_to_the_configured_application() => _token.Audiences.ShouldContain(Audience);
    [Fact] void should_bind_the_request_method() => Claim(_token, SignInAttestationClaims.HttpMethod).ShouldEqual("POST");
    [Fact] void should_bind_the_request_target_without_query_or_fragment() => Claim(_token, SignInAttestationClaims.HttpUri).ShouldEqual("https://studio.example.com/api/internal/sign-ins");
    [Fact] void should_bind_the_digest_of_the_exact_body_bytes() => Claim(_token, SignInAttestationClaims.BodyHash).ShouldEqual(Digest(Body));
    [Fact] void should_bind_the_time_it_was_issued() => _token.ValidFrom.ShouldEqual(_now.UtcDateTime);
    [Fact] void should_bind_the_time_it_expires() => _token.ValidTo.ShouldEqual(_now.AddSeconds(60).UtcDateTime);
    [Fact] void should_bind_a_replay_identifier() => _token.Id.ShouldNotBeEmpty();
    [Fact] void should_separate_itself_from_every_other_assertion_signed_with_the_same_key() => Claim(_token, SignInAttestationClaims.Purpose).ShouldEqual(SignInAttestationClaims.NotificationPurpose);
}
