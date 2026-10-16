// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SignInReturnUrl;

public class when_an_absolute_url_only_ends_with_a_declared_host : given.a_sign_in_request
{
    void Because() => Resolve("https://evilconsole.example.test/x");

    [Fact] void should_reduce_it() => _result.ShouldEqual("/x");
}
