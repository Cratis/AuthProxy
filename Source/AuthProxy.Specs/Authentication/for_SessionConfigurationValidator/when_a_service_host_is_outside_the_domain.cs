// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SessionConfigurationValidator;

public class when_a_service_host_is_outside_the_domain : given.a_session_validator
{
    void Establish()
    {
        _config.Session.CookieDomain = ".example.test";
        _config.Services["console"] = Routable("console.example.test");
        _config.Services["other"] = Routable("console.other.test");
        _config.Services["lookalike"] = Routable("notexample.test");
    }

    void Because() => Validate();

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_the_host_outside_the_domain() => Reports("console.other.test").ShouldBeTrue();
    [Fact] void should_refuse_a_host_that_only_ends_with_the_same_letters() => Reports("notexample.test").ShouldBeTrue();
    [Fact] void should_not_complain_about_a_host_inside_the_domain() => Reports("host 'console.example.test'").ShouldBeFalse();
}
