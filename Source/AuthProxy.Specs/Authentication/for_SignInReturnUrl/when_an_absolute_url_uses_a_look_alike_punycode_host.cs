// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SignInReturnUrl;

public class when_an_absolute_url_uses_a_look_alike_punycode_host : given.a_sign_in_request
{
    void Because() => Resolve($"https://{new System.Globalization.IdnMapping().GetAscii("cönsole.example.test")}/x");

    [Fact] void should_reduce_it() => _result.ShouldEqual("/x");
}
