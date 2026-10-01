// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens.for_AccessTokenConfigurationValidator;

public class when_no_oidc_provider_is_configured : given.an_access_token_validator
{
    void Establish() => _authentication.OidcProviders = [];

    void Because() => Validate();

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
}
