// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SessionCookieHealingMiddleware;

public class when_no_domain_is_configured : given.a_healing_middleware
{
    void Establish()
    {
        _session.CookieDomain = string.Empty;
        SendCookies($"{Cookie}=not-a-protected-ticket", $"{Cookie}=twice");
    }

    async Task Because() => await Invoke();

    [Fact] void should_delete_nothing() => SetCookies.ShouldBeEmpty();
    [Fact] void should_pass_the_request_on() => _nextWasCalled.ShouldBeTrue();
}
