// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_SignInNotificationSigner.given;

namespace Cratis.AuthProxy.SignIns.for_SignInNotificationSigner.when_issuing_an_envelope;

/// <summary>
/// Unusable key material is reported, never thrown — a sign-in must not break because a secret was mounted
/// wrong, and it must not be recorded on unauthenticated evidence either.
/// </summary>
public class and_the_signing_key_is_malformed : a_sign_in_notification_signer
{
    protected override string PrivateKeyPem(string valid) => "-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----";

    Exception _exception;
    bool _issued;
    string _envelope;

    void Because() => _exception = Catch.Exception(() => _issued = _signer.TryIssue(HttpMethod.Post, Target, Body, out _envelope));

    [Fact] void should_not_throw() => _exception.ShouldBeNull();
    [Fact] void should_not_issue_an_envelope() => _issued.ShouldBeFalse();
    [Fact] void should_not_hand_back_anything_that_could_be_sent() => _envelope.ShouldBeEmpty();
}
