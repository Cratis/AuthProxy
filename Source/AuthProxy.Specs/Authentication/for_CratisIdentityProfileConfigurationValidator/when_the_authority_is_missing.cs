// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_CratisIdentityProfileConfigurationValidator;

public class when_the_authority_is_missing : given.a_cratis_identity_provider
{
    void Because()
    {
        _provider.Authority = string.Empty;
        Validate();
    }

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_require_an_absolute_authority() => _result.FailureMessage.ShouldContain("Authority must be an absolute URL");
}
