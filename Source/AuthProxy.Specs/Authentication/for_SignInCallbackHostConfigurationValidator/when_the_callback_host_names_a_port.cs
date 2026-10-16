// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SignInCallbackHostConfigurationValidator;

public class when_the_callback_host_names_a_port : given.a_callback_host_validator
{
    void Establish() => CallbackHost("auth.example.test:8443");

    void Because() => Validate();

    [Fact] void should_succeed() => _result.Succeeded.ShouldBeTrue();
}
