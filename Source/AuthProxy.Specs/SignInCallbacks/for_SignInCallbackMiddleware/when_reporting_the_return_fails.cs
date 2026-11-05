// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignInCallbacks.for_SignInCallbackMiddleware;

/// <summary>
/// A callback never fails the request it rides on.
/// </summary>
public class when_reporting_the_return_fails : given.a_callback_middleware
{
    Exception? _exception;

    async Task Because()
    {
        _dispatcher
            .When(_ => _.Returned(Arg.Any<HttpContext>(), Arg.Any<string>(), Arg.Any<C.Service>(), Arg.Any<ClientPrincipal>(), Arg.Any<string?>()))
            .Do(_ => throw new InvalidOperationException("boom"));
        _exception = await Catch.Exception(() => _middleware.InvokeAsync(_context));
    }

    [Fact] void should_not_throw() => _exception.ShouldBeNull();
    [Fact] void should_forward_the_request() => _nextCalled.ShouldBeTrue();
}
