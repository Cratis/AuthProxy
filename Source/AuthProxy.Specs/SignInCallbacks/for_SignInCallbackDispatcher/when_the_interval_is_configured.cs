// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignInCallbacks.for_SignInCallbackDispatcher;

public class when_the_interval_is_configured : given.a_dispatcher
{
    protected override C.SignInCallback? Callback => new() { Path = CallbackPath, Interval = TimeSpan.FromMinutes(30) };

    void Because()
    {
        Return();
        _time.Advance(TimeSpan.FromMinutes(31));
        Return();
    }

    [Fact] void should_follow_the_configured_interval() => _queue.Requests.Count.ShouldEqual(2);
}
