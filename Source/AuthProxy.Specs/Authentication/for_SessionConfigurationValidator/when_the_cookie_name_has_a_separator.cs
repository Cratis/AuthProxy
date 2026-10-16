// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SessionConfigurationValidator;

public class when_the_cookie_name_has_a_separator : given.a_session_validator
{
    void Establish() => _config.Session.CookieName = "my cookie;name";

    void Because() => Validate();

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_say_it_is_not_a_valid_cookie_name() => Reports("not a valid cookie name").ShouldBeTrue();
}
