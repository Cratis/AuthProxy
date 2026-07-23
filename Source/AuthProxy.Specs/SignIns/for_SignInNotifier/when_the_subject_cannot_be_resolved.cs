// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_SignInNotifier.given;

namespace Cratis.AuthProxy.SignIns.for_SignInNotifier;

public class when_the_subject_cannot_be_resolved : a_sign_in_notifier
{
    SignInNotificationResult _result;

    protected override ClaimsPrincipal CreatePrincipal() => new(new ClaimsIdentity([new Claim("name", "Ada")], "github"));

    async Task Because() => _result = await _notifier.Notify(_httpContext, _principal);

    [Fact] void should_fail() => _result.ShouldEqual(SignInNotificationResult.Failed);
    [Fact] void should_not_post_anything() => _handler.LastRequest.ShouldBeNull();
}
