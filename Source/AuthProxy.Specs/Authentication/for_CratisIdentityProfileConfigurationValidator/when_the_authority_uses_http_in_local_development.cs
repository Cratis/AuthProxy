// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_CratisIdentityProfileConfigurationValidator;

public class when_the_authority_uses_http_in_local_development : given.a_cratis_identity_provider
{
    void Because()
    {
        _provider.Authority = "http://localhost:5100/realms/products";
        _configuration.Profile = C.DeploymentProfile.LocalDevelopment;
        Validate();
    }

    [Fact] void should_succeed() => _result.Succeeded.ShouldBeTrue();
}
