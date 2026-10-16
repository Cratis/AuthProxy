// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SignInReturnUrl;

public class when_no_url_is_given : given.a_sign_in_request
{
    void Because() => Resolve(string.Empty);

    [Fact] void should_go_to_the_application_root() => _result.ShouldEqual("/");
}
