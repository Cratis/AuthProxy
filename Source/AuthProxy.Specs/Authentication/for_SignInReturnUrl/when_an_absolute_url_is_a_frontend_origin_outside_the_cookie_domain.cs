// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SignInReturnUrl;

public class when_an_absolute_url_is_a_frontend_origin_outside_the_cookie_domain : given.a_sign_in_request
{
    void Establish() => _config.Services["console"].Frontend = new() { BaseUrl = "http://frontend.internal:8080/" };

    void Because() => Resolve("http://frontend.internal:8080/x");

    [Fact] void should_reduce_it() => _result.ShouldEqual("/x");
}
