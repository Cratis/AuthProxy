// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_SignInNotifier.given;

namespace Cratis.AuthProxy.SignIns.for_SignInNotifier.when_sending_verified_upstream_claims;

/// <summary>Without a validated access token nothing is sent — the identity token alone never speaks for the access token's claims.</summary>
public class and_there_is_no_validated_access_token : a_verified_claims_sign_in_notifier
{
    bool _present;

    async Task Because()
    {
        TheHandlerValidated(Scheme, [("iss", "https://idp.example.com"), ("sub", "acct-1"), ("github_id", "999")], null);
        await _notifier.Notify(_httpContext, _principal, Scheme);
        _present = PostedVerifiedClaims(out _);
    }

    [Fact] void should_send_no_verified_claims() => _present.ShouldBeFalse();
}
