// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_CanonicalIdentityConfigurationValidator;

public class when_the_verified_email_endpoint_is_not_https : given.a_valid_authentication_configuration
{
    void Establish() => _authentication.OAuthProviders[0].VerifiedEmailEndpoint = "http://api.github.example.com/user/emails";

    void Because() => Validate();

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_report_the_endpoint() => _result.Failures.ShouldContain("OAuth verified-email endpoints must be absolute HTTPS URLs, except for loopback development endpoints.");
}
