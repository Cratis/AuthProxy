// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignInCallbacks.for_SignInCallbackDispatcher;

public class when_a_user_returns_straight_after_signing_in : given.a_dispatcher
{
    void Because()
    {
        SignIn();
        Return();
    }

    [Fact] void should_report_one_callback() => _queue.Requests.Count.ShouldEqual(1);
    [Fact] void should_report_the_sign_in() => _queue.Requests[0].Kind.ShouldEqual(SignInCallbackKind.SignedIn);
}
