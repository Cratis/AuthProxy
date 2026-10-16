// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SignInReturnUrl;

public class when_the_url_is_ftp_on_a_declared_host : given.a_sign_in_request
{
    void Because() => Resolve("ftp://console.example.test/x");

    [Fact] void should_go_to_the_application_root() => _result.ShouldEqual("/");
}
