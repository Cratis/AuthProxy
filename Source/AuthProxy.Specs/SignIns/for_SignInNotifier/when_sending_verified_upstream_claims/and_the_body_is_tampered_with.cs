// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using Cratis.AuthProxy.SignIns.for_SignInNotifier.given;

namespace Cratis.AuthProxy.SignIns.for_SignInNotifier.when_sending_verified_upstream_claims;

/// <summary>The claims sit inside the digest-bound body, so changing one no longer matches the signed digest.</summary>
public class and_the_body_is_tampered_with : a_verified_claims_sign_in_notifier
{
    string _boundDigest;
    string _digestOfWhatWasSent;
    string _digestOfTheTamperedBody;

    async Task Because()
    {
        TheHandlerValidated(Scheme, ("sub", "acct-1"), ("github_id", "777"));
        await _notifier.Notify(_httpContext, _principal, Scheme);
        _boundDigest = Claim(Read(_handler.LastRequestAuthorization!.Parameter!), SignInAttestationClaims.BodyHash);
        var sent = _handler.LastRequestBytes.ToArray();
        _digestOfWhatWasSent = Digest(sent);
        _digestOfTheTamperedBody = Digest(Encoding.UTF8.GetBytes(
            Encoding.UTF8.GetString(sent).Replace("777", "778", StringComparison.Ordinal)));
    }

    [Fact] void should_bind_the_body_that_carried_the_claims() => _boundDigest.ShouldEqual(_digestOfWhatWasSent);
    [Fact] void should_not_match_a_body_with_an_altered_claim() => (_boundDigest == _digestOfTheTamperedBody).ShouldBeFalse();
    [Fact] void should_have_altered_a_claim_that_was_there() => (_digestOfTheTamperedBody == _digestOfWhatWasSent).ShouldBeFalse();
}
