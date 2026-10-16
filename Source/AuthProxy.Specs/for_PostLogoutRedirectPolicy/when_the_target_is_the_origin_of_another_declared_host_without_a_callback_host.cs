// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_PostLogoutRedirectPolicy;

public class when_the_target_is_the_origin_of_another_declared_host_without_a_callback_host : given.a_logout_request
{
    void Because() => Check("https://operations.example.test/");

    [Fact] void should_not_allow_it_because_only_a_callback_host_moves_people_between_hosts() => _allowed.ShouldBeFalse();
}
