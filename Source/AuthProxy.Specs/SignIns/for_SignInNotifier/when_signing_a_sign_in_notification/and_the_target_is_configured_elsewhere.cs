// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_SignInNotifier.given;

namespace Cratis.AuthProxy.SignIns.for_SignInNotifier.when_signing_a_sign_in_notification;

/// <summary>
/// The route binding follows the request rather than a constant: pointing the notification at a different
/// application moves the bound target with it, so an envelope minted for one receiver cannot be replayed at
/// another.
/// </summary>
public class and_the_target_is_configured_elsewhere : a_signed_sign_in_notifier
{
    const string OtherNotifyUrl = "https://lobby.example.com/internal/sign-ins";

    protected override string ConfiguredNotifyUrl => OtherNotifyUrl;

    string _boundTarget;

    async Task Because()
    {
        await _notifier.Notify(_httpContext, _principal);
        _boundTarget = Claim(Read(_handler.LastRequestAuthorization!.Parameter!), SignInAttestationClaims.HttpUri);
    }

    [Fact] void should_post_to_the_reconfigured_target() => _handler.LastRequest!.RequestUri!.ToString().ShouldEqual(OtherNotifyUrl);
    [Fact] void should_bind_the_reconfigured_target() => _boundTarget.ShouldEqual(OtherNotifyUrl);
    [Fact] void should_no_longer_bind_the_original_target() => (_boundTarget == NotifyUrl).ShouldBeFalse();
}
