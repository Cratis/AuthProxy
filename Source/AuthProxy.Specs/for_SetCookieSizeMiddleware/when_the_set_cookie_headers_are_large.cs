// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_SetCookieSizeMiddleware;

public class when_the_set_cookie_headers_are_large : given.a_set_cookie_size_middleware
{
    const string SecretValue = "super-secret-cookie-value";

    void Establish() => _setCookies =
    [
        $".AspNetCore.Cookies=C1{SecretValue}{new string('a', 2000)}; path=/",
        $".AspNetCore.CookiesC2={new string('b', 1800)}; path=/",
        "expired=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/"
    ];

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_warn_once() => WarningsLogged.ShouldEqual(1);
    [Fact] void should_name_the_first_cookie() => LoggedMessage.ShouldContain(".AspNetCore.Cookies (");
    [Fact] void should_name_the_second_cookie() => LoggedMessage.ShouldContain(".AspNetCore.CookiesC2 (");
    [Fact] void should_name_the_request_path() => LoggedMessage.ShouldContain("/signin-google");
    [Fact] void should_not_log_a_cookie_value() => LoggedMessage.Contains(SecretValue).ShouldBeFalse();
}
