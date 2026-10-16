// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SessionCookieHealingMiddleware;

public class when_the_caller_is_already_authenticated : given.a_healing_middleware
{
    void Establish()
    {
        SendCookies($"{Cookie}=a-valid-ticket");
        _context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Name, "someone")], "cookie"));
    }

    async Task Because() => await Invoke();

    [Fact] void should_delete_nothing() => SetCookies.ShouldBeEmpty();
    [Fact] void should_pass_the_request_on() => _nextWasCalled.ShouldBeTrue();
}
