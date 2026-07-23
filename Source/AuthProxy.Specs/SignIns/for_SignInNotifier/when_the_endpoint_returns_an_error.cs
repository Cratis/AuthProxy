// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.SignIns.for_SignInNotifier.given;

namespace Cratis.AuthProxy.SignIns.for_SignInNotifier;

public class when_the_endpoint_returns_an_error : a_sign_in_notifier
{
    SignInNotificationResult _result;

    protected override HttpStatusCode NotifyStatusCode => HttpStatusCode.InternalServerError;

    async Task Because() => _result = await _notifier.Notify(_httpContext, _principal);

    [Fact] void should_fail() => _result.ShouldEqual(SignInNotificationResult.Failed);
    [Fact] void should_still_have_posted() => _handler.LastRequest.ShouldNotBeNull();
}
