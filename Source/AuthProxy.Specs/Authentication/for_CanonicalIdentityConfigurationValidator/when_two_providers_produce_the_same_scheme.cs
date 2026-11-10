// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_CanonicalIdentityConfigurationValidator;

public class when_two_providers_produce_the_same_scheme : given.a_valid_authentication_configuration
{
    void Establish() => _authentication.OAuthProviders = [OAuthProvider("Entra", "github")];

    void Because() => Validate();

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_report_the_scheme_collision() => _result.Failures.ShouldContain("Authentication provider names must produce distinct schemes.");
}
