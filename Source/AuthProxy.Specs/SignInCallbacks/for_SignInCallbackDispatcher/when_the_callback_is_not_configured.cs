// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignInCallbacks.for_SignInCallbackDispatcher;

/// <summary>
/// The feature is off unless a service asks for it: neither a sign-in nor a return reaches the queue.
/// </summary>
public class when_the_callback_is_not_configured : given.a_dispatcher
{
    protected override C.SignInCallback? Callback => null;

    void Because()
    {
        SignIn();
        Return();
    }

    [Fact] void should_queue_nothing() => _queue.Requests.ShouldBeEmpty();
}
