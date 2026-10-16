// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SessionCookieHealingMiddleware;

public class when_the_request_carries_no_session_cookie : given.a_healing_middleware
{
    void Establish() => SendCookies("unrelated=value");

    async Task Because() => await Invoke();

    [Fact] void should_delete_nothing() => SetCookies.ShouldBeEmpty();
    [Fact] void should_pass_the_request_on() => _nextWasCalled.ShouldBeTrue();
}
