// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SessionConfigurationValidator;

public class when_the_domain_is_an_ip_address : given.a_session_validator
{
    void Establish() => _config.Session.CookieDomain = "10.0.0.1";

    void Because() => Validate();

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_say_it_is_an_ip_address() => Reports("IP address").ShouldBeTrue();
}
