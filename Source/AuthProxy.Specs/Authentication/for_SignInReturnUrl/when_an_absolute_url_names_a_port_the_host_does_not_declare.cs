// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SignInReturnUrl;

public class when_an_absolute_url_names_a_port_the_host_does_not_declare : given.a_sign_in_request
{
    void Because() => Resolve("https://console.example.test:8081/x");

    [Fact] void should_reduce_it() => _result.ShouldEqual("/x");
}
