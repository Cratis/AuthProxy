// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignInCallbacks.for_SignInCallbackMiddleware;

public class when_a_returning_user_makes_a_request : given.a_callback_middleware
{
    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_report_the_return() =>
        _dispatcher.Received(1).Returned(_context, "app", _service, Arg.Is<ClientPrincipal>(_ => _.UserId == "user-1"), "tenant-a");

    [Fact] void should_forward_the_request() => _nextCalled.ShouldBeTrue();
}
