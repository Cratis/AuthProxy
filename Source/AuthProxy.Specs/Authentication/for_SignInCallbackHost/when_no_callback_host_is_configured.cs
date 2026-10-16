// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SignInCallbackHost;

public class when_no_callback_host_is_configured : given.a_proxy_on_one_of_its_hosts
{
    void Establish() => _config.SignIn = null;

    void Because() => BounceLogin("/dashboard");

    [Fact] void should_not_bounce() => _bounced.ShouldBeFalse();
}
