// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using Cratis.AuthProxy.SignIns.for_SignInNotifier.given;

namespace Cratis.AuthProxy.SignIns.for_SignInNotifier.when_signing_a_sign_in_notification;

/// <summary>
/// The attack the body binding exists to stop: something between AuthProxy and the application keeps the
/// envelope and swaps the subject in the body. The digest is taken from the bytes the transport received, so
/// the altered body no longer matches while the untouched one still does.
/// </summary>
public class and_the_body_is_altered_in_flight : a_signed_sign_in_notifier
{
    string _boundDigest;
    string _digestOfWhatWasSent;
    string _digestOfTheAlteredBody;

    async Task Because()
    {
        await _notifier.Notify(_httpContext, _principal);
        _boundDigest = Claim(Read(_handler.LastRequestAuthorization!.Parameter!), SignInAttestationClaims.BodyHash);

        var sent = _handler.LastRequestBytes.ToArray();
        _digestOfWhatWasSent = Digest(sent);
        _digestOfTheAlteredBody = Digest(Encoding.UTF8.GetBytes(
            Encoding.UTF8.GetString(sent).Replace("subject-123", "subject-124", StringComparison.Ordinal)));
    }

    [Fact] void should_match_the_body_that_was_actually_sent() => _boundDigest.ShouldEqual(_digestOfWhatWasSent);
    [Fact] void should_not_match_the_altered_body() => (_boundDigest == _digestOfTheAlteredBody).ShouldBeFalse();
    [Fact] void should_have_altered_something_that_was_really_there() => (_digestOfTheAlteredBody == _digestOfWhatWasSent).ShouldBeFalse();
}
