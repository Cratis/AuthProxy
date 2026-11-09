// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using Cratis.AuthProxy.SignIns.for_SignInNotifier.given;

namespace Cratis.AuthProxy.SignIns.for_SignInNotifier.when_sending_verified_upstream_claims;

/// <summary>Without the opt-in the notification is exactly what it was, even if a validated token is on hand.</summary>
public class and_the_option_is_off : a_verified_claims_sign_in_notifier
{
    string _withOptionOff;
    string _released;

    protected override bool IncludesVerifiedClaims => false;

    async Task Because()
    {
        TheHandlerValidated(Scheme, ("iss", "https://idp.example.com"), ("sub", "acct-1"));
        await _notifier.Notify(_httpContext, _principal, Scheme);
        _withOptionOff = Encoding.UTF8.GetString(_handler.LastRequestBytes.Span);
        _released = (await NotifyThroughTheReleasedNotifier()).LastRequestBody!;
    }

    [Fact] void should_send_no_verified_claims() => _withOptionOff.Contains("verifiedClaims").ShouldBeFalse();
    [Fact] void should_send_the_released_body() => _withOptionOff.ShouldEqual(_released);
}
