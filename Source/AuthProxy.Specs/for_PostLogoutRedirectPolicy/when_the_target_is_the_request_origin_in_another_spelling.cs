// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_PostLogoutRedirectPolicy;

public class when_the_target_is_the_request_origin_in_another_spelling : given.a_logout_request
{
    void Because() => Check("https://CONSOLE.example.test:443/");

    [Fact] void should_allow_it() => _allowed.ShouldBeTrue();
}
