// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SessionConfigurationValidator;

public class when_the_domain_names_a_port : given.a_session_validator
{
    void Establish() => _config.Session.CookieDomain = "example.test:8443";

    void Because() => Validate();

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_say_it_names_a_port() => Reports("port").ShouldBeTrue();
}
