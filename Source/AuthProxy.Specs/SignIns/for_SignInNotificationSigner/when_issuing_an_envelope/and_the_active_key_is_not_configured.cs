// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_SignInNotificationSigner.given;

namespace Cratis.AuthProxy.SignIns.for_SignInNotificationSigner.when_issuing_an_envelope;

/// <summary>
/// A rotation that names a key nobody holds must fail loudly rather than mint an envelope under whatever key
/// happens to be first in the list.
/// </summary>
public class and_the_active_key_is_not_configured : a_sign_in_notification_signer
{
    protected override string ActiveKeyId => "a-key-that-was-retired";

    bool _issued;
    string _envelope;

    void Because() => _issued = _signer.TryIssue(HttpMethod.Post, Target, Body, out _envelope);

    [Fact] void should_not_issue_an_envelope() => _issued.ShouldBeFalse();
    [Fact] void should_not_hand_back_anything_that_could_be_sent() => _envelope.ShouldBeEmpty();
    [Fact] void should_still_report_signing_as_enabled() => _signer.IsEnabled.ShouldBeTrue();
}
