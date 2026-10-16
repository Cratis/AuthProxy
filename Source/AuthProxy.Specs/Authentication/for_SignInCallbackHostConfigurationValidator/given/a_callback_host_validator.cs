// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SignInCallbackHostConfigurationValidator.given;

public class a_callback_host_validator : Specification
{
    protected C.AuthProxy _config;
    protected ValidateOptionsResult _result;

    void Establish() => _config = new() { Session = new() { CookieDomain = ".example.test" }, SignIn = new() };

    protected void CallbackHost(string value) => _config.SignIn!.CallbackHost = value;

    protected void Validate() => _result = new SignInCallbackHostConfigurationValidator().Validate(null, _config);

    protected bool Reports(string fragment) => _result.Failures?.Any(_ => _.Contains(fragment)) == true;
}
