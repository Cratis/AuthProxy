// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SignInReturnUrl;

public class when_an_absolute_url_is_outside_the_cookie_domain : given.a_sign_in_request
{
    void Establish() => _config.Logout.AllowedRedirectOrigins = ["https://marketing.other.test"];

    void Because() => Resolve("https://marketing.other.test/landing");

    [Fact] void should_reduce_it_even_though_logout_may_go_there() => _result.ShouldEqual("/landing");
}
