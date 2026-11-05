// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignInCallbacks.for_SignInCallbackDispatcher;

public class when_a_user_returns_again_within_the_interval : given.a_dispatcher
{
    void Because()
    {
        Return();
        _time.Advance(TimeSpan.FromHours(11) + TimeSpan.FromMinutes(59));
        Return();
    }

    [Fact] void should_report_the_return_once() => _queue.Requests.Count.ShouldEqual(1);
}
