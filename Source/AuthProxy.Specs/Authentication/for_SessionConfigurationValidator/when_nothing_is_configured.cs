// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SessionConfigurationValidator;

public class when_nothing_is_configured : given.a_session_validator
{
    void Establish() => _config.Services["one"] = Routable("anywhere.test");

    void Because() => Validate();

    [Fact] void should_succeed() => _result.Succeeded.ShouldBeTrue();
}
