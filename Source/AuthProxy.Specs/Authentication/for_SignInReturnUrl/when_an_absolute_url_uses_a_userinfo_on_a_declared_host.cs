// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SignInReturnUrl;

public class when_an_absolute_url_uses_a_userinfo_on_a_declared_host : given.a_sign_in_request
{
    void Because() => Resolve("https://someone:secret@console.example.test/x");

    [Fact] void should_not_keep_the_user_information() => _result.ShouldEqual("/x");
}
