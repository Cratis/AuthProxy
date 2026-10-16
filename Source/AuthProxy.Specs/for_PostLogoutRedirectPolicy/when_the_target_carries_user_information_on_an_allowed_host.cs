// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_PostLogoutRedirectPolicy;

public class when_the_target_carries_user_information_on_an_allowed_host : given.a_logout_request
{
    void Because() => Check("https://someone@console.example.test/");

    [Fact] void should_not_allow_it() => _allowed.ShouldBeFalse();
}
