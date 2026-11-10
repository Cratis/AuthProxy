// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_CanonicalIdentityConfigurationValidator;

public class when_the_verified_email_endpoint_is_loopback_http : given.a_valid_authentication_configuration
{
    void Establish() => _authentication.OAuthProviders[0].VerifiedEmailEndpoint = "http://localhost:5000/user/emails";

    void Because() => Validate();

    [Fact] void should_succeed() => _result.Succeeded.ShouldBeTrue();
}
