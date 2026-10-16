// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SignInReturnUrl;

public class when_the_url_is_relative : given.a_sign_in_request
{
    void Because() => Resolve("/dashboard?tab=2");

    [Fact] void should_keep_it() => _result.ShouldEqual("/dashboard?tab=2");
}
