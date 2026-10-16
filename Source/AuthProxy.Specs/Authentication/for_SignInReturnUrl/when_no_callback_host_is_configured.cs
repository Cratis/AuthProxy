// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SignInReturnUrl;

public class when_no_callback_host_is_configured : given.a_sign_in_request
{
    void Establish() => _config.SignIn = null;

    void Because() => Resolve("https://console.example.test/dashboard");

    [Fact] void should_still_reduce_an_absolute_url_to_its_path_and_query() => _result.ShouldEqual("/dashboard");
}
