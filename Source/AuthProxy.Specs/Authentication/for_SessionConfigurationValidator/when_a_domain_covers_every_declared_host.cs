// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SessionConfigurationValidator;

public class when_a_domain_covers_every_declared_host : given.a_session_validator
{
    void Establish()
    {
        _config.Session.CookieDomain = ".Example.Test";
        _config.Services["console"] = Routable("console.example.test");
        _config.Services["operations"] = Routable("operations.example.test:8443");
        _config.Services["apex"] = Routable("example.test");
    }

    void Because() => Validate();

    [Fact] void should_succeed() => _result.Succeeded.ShouldBeTrue();
}
