// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_CratisIdentityProfileConfigurationValidator;

public class when_no_client_secret_is_configured : given.a_cratis_identity_provider
{
    void Because()
    {
        _provider.ClientSecret = string.Empty;
        Validate();
    }

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_require_a_confidential_client() => _result.FailureMessage.ShouldContain("confidential client is required");
}
