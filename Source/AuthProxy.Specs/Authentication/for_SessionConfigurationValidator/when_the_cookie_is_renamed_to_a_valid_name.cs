// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SessionConfigurationValidator;

public class when_the_cookie_is_renamed_to_a_valid_name : given.a_session_validator
{
    void Establish()
    {
        _config.Session.CookieDomain = ".example.test";
        _config.Session.CookieName = ".Cratis.Studio.Auth";
    }

    void Because() => Validate();

    [Fact] void should_succeed() => _result.Succeeded.ShouldBeTrue();
}
