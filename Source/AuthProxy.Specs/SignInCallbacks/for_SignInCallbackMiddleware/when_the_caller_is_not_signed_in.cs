// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignInCallbacks.for_SignInCallbackMiddleware;

public class when_the_caller_is_not_signed_in : given.a_callback_middleware
{
    protected override bool Authenticated => false;

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_report_nothing() =>
        _dispatcher.DidNotReceiveWithAnyArgs().Returned(default!, default!, default!, default!, default);

    [Fact] void should_forward_the_request() => _nextCalled.ShouldBeTrue();
}
