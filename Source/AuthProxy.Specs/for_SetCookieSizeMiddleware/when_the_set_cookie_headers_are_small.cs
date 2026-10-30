// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_SetCookieSizeMiddleware;

public class when_the_set_cookie_headers_are_small : given.a_set_cookie_size_middleware
{
    void Establish() => _setCookies = [".AspNetCore.Cookies=" + new string('a', 900) + "; path=/; httponly"];

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_warn() => WarningsLogged.ShouldEqual(0);
}
