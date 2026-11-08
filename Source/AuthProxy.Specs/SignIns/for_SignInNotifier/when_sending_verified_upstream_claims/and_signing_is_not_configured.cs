// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using Cratis.AuthProxy.SignIns.for_SignInNotifier.given;

namespace Cratis.AuthProxy.SignIns.for_SignInNotifier.when_sending_verified_upstream_claims;

/// <summary>With no signed envelope the claims have nothing to be bound by, so none are sent.</summary>
public class and_signing_is_not_configured : a_verified_claims_sign_in_notifier
{
    string _body;

    protected override C.SignInAttestation? CreateAttestation() => null;

    async Task Because()
    {
        TheHandlerValidated(Scheme, ("sub", "acct-1"));
        await _notifier.Notify(_httpContext, _principal, Scheme);
        _body = Encoding.UTF8.GetString(_handler.LastRequestBytes.Span);
    }

    [Fact] void should_send_no_verified_claims() => _body.Contains("verifiedClaims").ShouldBeFalse();
    [Fact] void should_send_no_credential() => _handler.LastRequestAuthorization.ShouldBeNull();
}
