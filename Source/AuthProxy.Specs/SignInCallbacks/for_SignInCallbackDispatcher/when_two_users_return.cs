// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignInCallbacks.for_SignInCallbackDispatcher;

public class when_two_users_return : given.a_dispatcher
{
    void Because()
    {
        Return("user-1");
        Return("user-2");
    }

    [Fact] void should_report_each_of_them() => _queue.Requests.Count.ShouldEqual(2);
}
