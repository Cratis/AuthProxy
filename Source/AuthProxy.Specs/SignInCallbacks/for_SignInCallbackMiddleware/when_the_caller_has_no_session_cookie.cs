// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignInCallbacks.for_SignInCallbackMiddleware;

/// <summary>
/// A caller authenticated some other way than by the browser session — a bearer token, say — never signed in here,
/// so it is not a returning user.
/// </summary>
public class when_the_caller_has_no_session_cookie : given.a_callback_middleware
{
    protected override string Scheme => "Bearer";

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_report_nothing() =>
        _dispatcher.DidNotReceiveWithAnyArgs().Returned(default!, default!, default!, default!, default);

    [Fact] void should_forward_the_request() => _nextCalled.ShouldBeTrue();
}
