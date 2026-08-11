// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_SignInNotificationSigner.given;

namespace Cratis.AuthProxy.SignIns.for_SignInNotificationSigner.when_issuing_an_envelope;

/// <summary>
/// Startup validation should never let this configuration through — but the signer is the last thing standing
/// between a bad configuration and the sign-in itself. An exception here escapes issuing, escapes notifying,
/// and breaks the sign-in AuthProxy was only supposed to record, so resolving the active key must not be able
/// to throw whatever the key list looks like.
/// </summary>
public class and_the_active_key_identifier_is_duplicated : a_sign_in_notification_signer
{
    bool _issued;
    string _envelope;
    Exception _error;

    void Establish() =>
        _configuration.SignIn!.Attestation!.SigningKeys.Add(new C.SignInAttestationSigningKey
        {
            KeyId = KeyId,
            PrivateKeyPem = _configuration.SignIn.Attestation.SigningKeys[0].PrivateKeyPem,
        });

    void Because() => _error = Catch.Exception(() => _issued = _signer.TryIssue(HttpMethod.Post, Target, Body, out _envelope));

    [Fact] void should_not_throw_out_of_the_sign_in() => _error.ShouldBeNull();
    [Fact] void should_still_issue_the_envelope() => _issued.ShouldBeTrue();
}
