// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfConfigurationValidator.when_validating;

public class and_the_permitted_services_are_listed : Specification
{
    ValidateOptionsResult _result;

    void Because()
    {
        var configuration = new OnBehalfConfiguration().Value;
        configuration.Services["lobby"] = new()
        {
            Backend = new() { BaseUrl = "https://lobby.internal" },
            IdentityVerification = C.IdentityVerificationMode.Required,
        };
        configuration.OnBehalf!.Services = [OnBehalfConfiguration.ServiceName, "Lobby"];
        _result = new OnBehalfConfigurationValidator().Validate(null, configuration);
    }

    [Fact] void should_succeed() => _result.Succeeded.ShouldBeTrue();
}
