// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_CratisIdentityProfileConfigurationValidator;

public class when_the_provider_is_not_a_cratis_identity_provider : given.a_cratis_identity_provider
{
    void Because()
    {
        _provider.Type = C.OidcProviderType.Custom;
        _provider.Authority = "http://identity.cratis.example";
        _provider.ClientSecret = string.Empty;
        Validate();
    }

    [Fact] void should_leave_it_to_the_existing_rules() => _result.Succeeded.ShouldBeTrue();
}
