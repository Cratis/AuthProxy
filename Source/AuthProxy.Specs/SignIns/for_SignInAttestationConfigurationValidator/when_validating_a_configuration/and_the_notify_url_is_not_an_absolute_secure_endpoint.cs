// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_SignInAttestationConfigurationValidator.given;

namespace Cratis.AuthProxy.SignIns.for_SignInAttestationConfigurationValidator.when_validating_a_configuration;

/// <summary>
/// The route binding is only as meaningful as the target it names, so a signing deployment has to point at an
/// absolute, secure endpoint — with loopback still allowed for development, as everywhere else in AuthProxy.
/// </summary>
public class and_the_notify_url_is_not_an_absolute_secure_endpoint : a_sign_in_attestation_configuration
{
    ValidateOptionsResult _relative;
    ValidateOptionsResult _plainHttp;
    ValidateOptionsResult _loopback;

    void Because()
    {
        _relative = Validate(Configuration("/api/internal/sign-ins", signingKeys: PrivateKey("current")));
        _plainHttp = Validate(Configuration("http://studio.example.com/api/internal/sign-ins", signingKeys: PrivateKey("current")));
        _loopback = Validate(Configuration("http://localhost:5000/api/internal/sign-ins", signingKeys: PrivateKey("current")));
    }

    [Fact] void should_reject_a_relative_url() => _relative.Succeeded.ShouldBeFalse();
    [Fact] void should_reject_plain_http_to_a_remote_host() => _plainHttp.Succeeded.ShouldBeFalse();
    [Fact] void should_still_allow_loopback_for_development() => _loopback.Succeeded.ShouldBeTrue();
}
