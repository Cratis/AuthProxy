// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_ClientCredentialsConfigurationValidator;

public class when_the_family_lifetime_is_not_positive : Specification
{
    ValidateOptionsResult _result;

    void Because()
    {
        var options = new C.AuthProxy();
        options.Services["portal"] = new C.Service
        {
            ClientCredentials = new C.ServiceClientCredentials { RefreshTokenFamilyLifetime = TimeSpan.Zero },
        };

        _result = new ClientCredentialsConfigurationValidator().Validate(null, options);
    }

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_the_service() => _result.FailureMessage.ShouldContain("Services:portal:ClientCredentials:RefreshTokenFamilyLifetime");
}
