// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignInCallbacks.for_SignInCallbackDispatcher;

/// <summary>
/// A service that stops answering can fill the queue; the request that caused the callback must not notice.
/// </summary>
public class when_the_queue_is_full : given.a_dispatcher
{
    Exception? _exception;

    void Because()
    {
        _queue.Accepts = false;
        _exception = Catch.Exception(() =>
        {
            SignIn();
            Return();
        });
    }

    [Fact] void should_not_throw() => _exception.ShouldBeNull();
}
