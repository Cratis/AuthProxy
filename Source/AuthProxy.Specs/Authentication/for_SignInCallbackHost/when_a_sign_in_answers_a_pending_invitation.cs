// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SignInCallbackHost;

public class when_a_sign_in_answers_a_pending_invitation : given.a_proxy_on_one_of_its_hosts
{
    void Establish() => _context.Request.Headers.Cookie = $"{Cookies.InviteToken}=token";

    void Because() => BounceLogin("/dashboard");

    [Fact] void should_not_bounce_because_the_invitation_cookies_are_host_only() => _bounced.ShouldBeFalse();
}
