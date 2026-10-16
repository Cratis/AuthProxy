// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SignInCallbackHost;

public class when_a_sign_out_starts_on_the_callback_host : given.a_proxy_on_one_of_its_hosts
{
    void Establish() => _context.Request.Host = new HostString("auth.example.test");

    void Because() => BounceLogout("/goodbye");

    [Fact] void should_not_bounce() => _bounced.ShouldBeFalse();
}
