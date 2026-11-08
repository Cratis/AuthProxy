// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using Cratis.AuthProxy.SignIns.for_SignInNotifier.given;

namespace Cratis.AuthProxy.SignIns.for_SignInNotifier.when_sending_verified_upstream_claims;

/// <summary>Anything but a validated JSON web token yields no claims.</summary>
public class and_the_token_is_not_a_validated_jwt : a_verified_claims_sign_in_notifier
{
    string _body;

    async Task Because()
    {
        VerifiedUpstreamClaims.Capture(_httpContext, Scheme, null);
        await _notifier.Notify(_httpContext, _principal, Scheme);
        _body = Encoding.UTF8.GetString(_handler.LastRequestBytes.Span);
    }

    [Fact] void should_send_no_verified_claims() => _body.Contains("verifiedClaims").ShouldBeFalse();
}
