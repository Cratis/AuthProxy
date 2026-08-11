// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_SignInNotificationSigner.given;

namespace Cratis.AuthProxy.SignIns.for_SignInNotificationSigner.when_issuing_an_envelope;

/// <summary>
/// With no attestation section there is nothing to sign with and nothing to sign for — the signer says so,
/// and the notifier reads that as "post exactly what has always been posted".
/// </summary>
public class and_signing_is_not_configured : a_sign_in_notification_signer
{
    protected override bool SigningIsConfigured => false;

    bool _issued;
    string _envelope;

    void Because() => _issued = _signer.TryIssue(HttpMethod.Post, Target, Body, out _envelope);

    [Fact] void should_report_signing_as_disabled() => _signer.IsEnabled.ShouldBeFalse();
    [Fact] void should_not_issue_an_envelope() => _issued.ShouldBeFalse();
    [Fact] void should_not_hand_back_anything_that_could_be_sent() => _envelope.ShouldBeEmpty();
}
