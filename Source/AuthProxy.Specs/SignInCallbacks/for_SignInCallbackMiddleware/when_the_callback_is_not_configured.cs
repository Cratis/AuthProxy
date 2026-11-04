// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignInCallbacks.for_SignInCallbackMiddleware;

public class when_the_callback_is_not_configured : given.a_callback_middleware
{
    protected override C.SignInCallback? Callback => null;

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_report_nothing() =>
        _dispatcher.DidNotReceiveWithAnyArgs().Returned(default!, default!, default!, default!, default);

    [Fact] void should_forward_the_request() => _nextCalled.ShouldBeTrue();
}
