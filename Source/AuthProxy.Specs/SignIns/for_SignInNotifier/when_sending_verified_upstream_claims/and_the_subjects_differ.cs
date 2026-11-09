// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_SignInNotifier.given;

namespace Cratis.AuthProxy.SignIns.for_SignInNotifier.when_sending_verified_upstream_claims;

/// <summary>A token pair that names two different subjects is not one sign-in: every claim is omitted.</summary>
public class and_the_subjects_differ : a_verified_claims_sign_in_notifier
{
    bool _present;

    async Task Because()
    {
        TheHandlerValidated(
            Scheme,
            [("iss", "https://idp.example.com"), ("sub", "acct-1")],
            [("sub", "acct-2"), ("github_id", "777")]);
        await _notifier.Notify(_httpContext, _principal, Scheme);
        _present = PostedVerifiedClaims(out _);
    }

    [Fact] void should_send_no_verified_claims() => _present.ShouldBeFalse();
}
