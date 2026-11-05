// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignInCallbacks.for_SignInCallbackDispatcher;

public class when_a_user_returns : given.a_dispatcher
{
    void Because() => Return();

    [Fact] void should_queue_one_callback() => _queue.Requests.Count.ShouldEqual(1);
    [Fact] void should_report_a_return() => _queue.Requests[0].Kind.ShouldEqual(SignInCallbackKind.Returned);
    [Fact] void should_carry_the_tenant() => _queue.Requests[0].Tenant.ShouldEqual(Tenant);
}
