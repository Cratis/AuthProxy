// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_SignInNotificationSigner.given;

namespace Cratis.AuthProxy.SignIns.for_SignInNotificationSigner.when_issuing_an_envelope;

/// <summary>
/// The replay binding, mutated on its own: two envelopes over an identical request at an identical instant
/// still differ, so a receiver can remember the identifiers it has already accepted.
/// </summary>
public class and_the_same_request_is_signed_twice : a_sign_in_notification_signer
{
    string _first;
    string _second;

    void Because()
    {
        _signer.TryIssue(HttpMethod.Post, Target, Body, out var first);
        _signer.TryIssue(HttpMethod.Post, Target, Body, out var second);
        _first = Read(first).Id;
        _second = Read(second).Id;
    }

    [Fact] void should_give_the_first_envelope_an_identifier() => _first.ShouldNotBeEmpty();
    [Fact] void should_never_repeat_it() => (_second == _first).ShouldBeFalse();
}
