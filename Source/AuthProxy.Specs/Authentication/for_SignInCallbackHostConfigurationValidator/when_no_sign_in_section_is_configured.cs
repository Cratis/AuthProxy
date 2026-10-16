// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SignInCallbackHostConfigurationValidator;

public class when_no_sign_in_section_is_configured : given.a_callback_host_validator
{
    void Establish() => _config.SignIn = null;

    void Because() => Validate();

    [Fact] void should_succeed() => _result.Succeeded.ShouldBeTrue();
}
