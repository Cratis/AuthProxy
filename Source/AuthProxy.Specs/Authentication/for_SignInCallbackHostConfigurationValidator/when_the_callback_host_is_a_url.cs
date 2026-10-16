// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SignInCallbackHostConfigurationValidator;

public class when_the_callback_host_is_a_url : given.a_callback_host_validator
{
    void Establish() => CallbackHost("https://auth.example.test/");

    void Because() => Validate();

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_say_it_is_not_a_host_name() => Reports("not a host name").ShouldBeTrue();
}
