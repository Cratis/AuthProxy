// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SignInCallbackHostConfigurationValidator;

public class when_the_callback_host_only_ends_with_the_same_letters_as_the_cookie_domain : given.a_callback_host_validator
{
    void Establish() => CallbackHost("notexample.test");

    void Because() => Validate();

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
}
