// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SessionConfigurationValidator;

public class when_the_cookie_name_is_blank : given.a_session_validator
{
    void Establish() => _config.Session.CookieName = "  ";

    void Because() => Validate();

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_the_setting() => Reports("CookieName").ShouldBeTrue();
}
