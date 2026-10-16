// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_PostLogoutRedirectPolicy;

public class when_the_target_hides_another_host_behind_user_information : given.a_logout_request
{
    void Because() => Check("https://console.example.test@evil.test/");

    [Fact] void should_not_allow_it() => _allowed.ShouldBeFalse();
}
