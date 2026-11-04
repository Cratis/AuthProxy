// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignInCallbacks.for_SignInCallbackDispatcher;

public class when_a_user_signs_in_again_within_the_interval : given.a_dispatcher
{
    void Because()
    {
        SignIn();
        _time.Advance(TimeSpan.FromMinutes(5));
        SignIn();
    }

    [Fact] void should_report_every_sign_in() => _queue.Requests.Count.ShouldEqual(2);
}
