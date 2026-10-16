// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SessionCookieHealingMiddleware;

public class when_the_session_cookie_is_sent_twice : given.a_healing_middleware
{
    void Establish() => SendCookies($"{Cookie}=host-only", $"{Cookie}=domain");

    async Task Because() => await Invoke();

    [Fact] void should_delete_the_host_only_copy() => Deleted(Cookie).ShouldBeTrue();
    [Fact] void should_pass_the_request_on() => _nextWasCalled.ShouldBeTrue();
}
