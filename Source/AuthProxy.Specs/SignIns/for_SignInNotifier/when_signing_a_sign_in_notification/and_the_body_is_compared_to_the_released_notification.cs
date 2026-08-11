// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using Cratis.AuthProxy.SignIns.for_SignInNotifier.given;

namespace Cratis.AuthProxy.SignIns.for_SignInNotifier.when_signing_a_sign_in_notification;

/// <summary>
/// Signing is additive: the envelope rides in a header and the JSON the application parses is unchanged.
/// The comparison is against the released four-argument notifier posting the same sign-in, so an application
/// that upgrades and enables signing never has to change how it reads the body.
/// </summary>
public class and_the_body_is_compared_to_the_released_notification : a_signed_sign_in_notifier
{
    byte[] _signedBytes;
    byte[] _releasedBytes;

    async Task Because()
    {
        await _notifier.Notify(_httpContext, _principal);
        _signedBytes = _handler.LastRequestBytes.ToArray();
        _releasedBytes = (await NotifyThroughTheReleasedNotifier()).LastRequestBytes.ToArray();
    }

    [Fact] void should_send_the_same_json() => Encoding.UTF8.GetString(_signedBytes).ShouldEqual(Encoding.UTF8.GetString(_releasedBytes));
    [Fact] void should_send_the_same_number_of_bytes() => _signedBytes.Length.ShouldEqual(_releasedBytes.Length);
    [Fact] void should_not_be_comparing_two_empty_bodies() => _releasedBytes.ShouldNotBeEmpty();
}
