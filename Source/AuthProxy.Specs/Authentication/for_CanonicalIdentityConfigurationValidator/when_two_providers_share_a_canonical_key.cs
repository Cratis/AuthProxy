// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_CanonicalIdentityConfigurationValidator;

public class when_two_providers_share_a_canonical_key : given.a_valid_authentication_configuration
{
    void Establish() => _authentication.OAuthProviders = [OAuthProvider("GitHub", "entra")];

    void Because() => Validate();

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_report_the_key_collision() => _result.Failures.ShouldContain("Canonical provider keys must be unique, lowercase, bounded ASCII identifiers.");
}
