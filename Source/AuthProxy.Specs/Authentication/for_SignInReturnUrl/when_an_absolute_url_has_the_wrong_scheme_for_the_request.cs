// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SignInReturnUrl;

public class when_an_absolute_url_has_the_wrong_scheme_for_the_request : given.a_sign_in_request
{
    void Because() => Resolve("http://console.example.test/downgraded");

    [Fact] void should_reduce_it_rather_than_allow_a_downgrade() => _result.ShouldEqual("/downgraded");
}
