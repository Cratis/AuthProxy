// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_SignInNotifier.given;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.SignIns.for_SignInNotifier.when_signing_a_sign_in_notification;

/// <summary>
/// The end-to-end pin: every binding is checked against what the transport actually received, not against
/// what the notifier intended to send. The digest in particular is compared to the bytes the handler read off
/// the request, so an envelope signed over anything other than the posted body fails here.
/// </summary>
public class and_the_envelope_is_verified : a_signed_sign_in_notifier
{
    SignInNotificationResult _result;
    JsonWebToken _envelope;
    TokenValidationResult _validation;

    async Task Because()
    {
        _result = await _notifier.Notify(_httpContext, _principal);
        _envelope = Read(_handler.LastRequestAuthorization!.Parameter!);
        _validation = await Validate(_handler.LastRequestAuthorization!.Parameter!);
    }

    [Fact] void should_notify() => _result.ShouldEqual(SignInNotificationResult.Notified);
    [Fact] void should_present_the_envelope_as_a_bearer_credential() => _handler.LastRequestAuthorization!.Scheme.ShouldEqual("Bearer");
    [Fact] void should_verify_against_the_pinned_public_key() => _validation.IsValid.ShouldBeTrue();
    [Fact] void should_name_the_signing_key() => _envelope.Kid.ShouldEqual(KeyId);
    [Fact] void should_bind_provenance_to_the_configured_issuer() => _envelope.Issuer.ShouldEqual(Issuer);
    [Fact] void should_bind_the_audience_to_the_configured_application() => _envelope.Audiences.ShouldContain(Audience);
    [Fact] void should_bind_the_method_the_request_was_sent_with() => Claim(_envelope, SignInAttestationClaims.HttpMethod).ShouldEqual(_handler.LastRequest!.Method.Method);
    [Fact] void should_bind_the_target_the_request_was_sent_to() => Claim(_envelope, SignInAttestationClaims.HttpUri).ShouldEqual(NotifyUrl);
    [Fact] void should_bind_the_digest_of_the_bytes_that_crossed_the_wire() => Claim(_envelope, SignInAttestationClaims.BodyHash).ShouldEqual(Digest(_handler.LastRequestBytes.ToArray()));
    [Fact] void should_bind_the_time_it_was_issued() => _envelope.ValidFrom.ShouldEqual(_now.UtcDateTime);
    [Fact] void should_bind_the_time_it_expires() => _envelope.ValidTo.ShouldEqual(_now.AddSeconds(60).UtcDateTime);
    [Fact] void should_bind_a_replay_identifier() => _envelope.Id.ShouldNotBeEmpty();
    [Fact] void should_have_posted_a_body_to_bind() => _handler.LastRequestBytes.Length.ShouldBeGreaterThan(0);
}
