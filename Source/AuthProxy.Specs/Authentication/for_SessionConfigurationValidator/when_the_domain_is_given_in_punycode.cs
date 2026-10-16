// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SessionConfigurationValidator;

public class when_the_domain_is_given_in_punycode : given.a_session_validator
{
    void Establish()
    {
        _config.Session.CookieDomain = ".xn--bcher-kva.example";
        _config.Services["shop"] = Routable("shop.bücher.example");
    }

    void Because() => Validate();

    [Fact] void should_succeed() => _result.Succeeded.ShouldBeTrue();
}
