// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SignInReturnUrl;

public class when_an_absolute_url_is_on_a_declared_host_with_a_port : given.a_sign_in_request
{
    void Because() => Resolve("https://operations.example.test:8443/users");

    [Fact] void should_keep_it() => _result.ShouldEqual("https://operations.example.test:8443/users");
}
