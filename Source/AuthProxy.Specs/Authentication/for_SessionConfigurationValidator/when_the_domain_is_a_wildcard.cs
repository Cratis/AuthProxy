// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SessionConfigurationValidator;

public class when_the_domain_is_a_wildcard : given.a_session_validator
{
    void Establish() => _config.Session.CookieDomain = "*.example.test";

    void Because() => Validate();

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_say_it_is_not_a_host_name() => Reports("not a host name").ShouldBeTrue();
}
