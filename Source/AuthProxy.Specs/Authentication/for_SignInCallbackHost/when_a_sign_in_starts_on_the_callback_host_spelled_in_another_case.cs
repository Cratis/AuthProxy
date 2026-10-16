// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SignInCallbackHost;

public class when_a_sign_in_starts_on_the_callback_host_spelled_in_another_case : given.a_proxy_on_one_of_its_hosts
{
    void Establish() => _context.Request.Host = new HostString("AUTH.Example.Test");

    void Because() => BounceLogin("/dashboard");

    [Fact] void should_not_bounce() => _bounced.ShouldBeFalse();
}
