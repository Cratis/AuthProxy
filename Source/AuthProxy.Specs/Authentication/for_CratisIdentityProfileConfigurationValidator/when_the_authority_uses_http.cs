// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_CratisIdentityProfileConfigurationValidator;

public class when_the_authority_uses_http : given.a_cratis_identity_provider
{
    void Because()
    {
        _provider.Authority = "http://identity.cratis.example/realms/products";
        Validate();
    }

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_require_https() => _result.FailureMessage.ShouldContain("must use HTTPS");
}
