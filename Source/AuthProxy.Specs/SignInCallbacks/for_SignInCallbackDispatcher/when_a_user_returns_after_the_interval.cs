// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignInCallbacks.for_SignInCallbackDispatcher;

public class when_a_user_returns_after_the_interval : given.a_dispatcher
{
    void Because()
    {
        Return();
        _time.Advance(TimeSpan.FromHours(12));
        Return();
    }

    [Fact] void should_report_the_return_again() => _queue.Requests.Count.ShouldEqual(2);
}
