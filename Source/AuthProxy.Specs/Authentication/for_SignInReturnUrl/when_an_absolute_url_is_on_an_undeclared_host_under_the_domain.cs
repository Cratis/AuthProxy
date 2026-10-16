// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SignInReturnUrl;

public class when_an_absolute_url_is_on_an_undeclared_host_under_the_domain : given.a_sign_in_request
{
    void Because() => Resolve("https://undeclared.example.test/phish?x=1");

    [Fact] void should_reduce_it_to_its_path_and_query_on_this_host() => _result.ShouldEqual("/phish?x=1");
}
