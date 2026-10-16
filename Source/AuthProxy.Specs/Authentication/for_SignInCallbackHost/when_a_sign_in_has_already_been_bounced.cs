// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SignInCallbackHost;

public class when_a_sign_in_has_already_been_bounced : given.a_proxy_on_one_of_its_hosts
{
    void Establish() => _context.Request.QueryString = QueryString.Create(SignInCallbackHost.BouncedQueryKey, "1");

    void Because() => BounceLogin("/dashboard");

    [Fact] void should_not_bounce_again_so_a_rewritten_host_header_cannot_loop() => _bounced.ShouldBeFalse();
}
