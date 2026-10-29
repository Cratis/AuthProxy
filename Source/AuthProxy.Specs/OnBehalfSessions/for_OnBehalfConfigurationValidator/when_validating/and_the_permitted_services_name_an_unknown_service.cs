// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfConfigurationValidator.when_validating;

public class and_the_permitted_services_name_an_unknown_service : Specification
{
    ValidateOptionsResult _result;

    void Because()
    {
        var configuration = new OnBehalfConfiguration().Value;
        configuration.OnBehalf!.Services = [OnBehalfConfiguration.ServiceName, "missing"];
        _result = new OnBehalfConfigurationValidator().Validate(null, configuration);
    }

    [Fact] void should_fail() => _result.FailureMessage.ShouldContain("OnBehalf.Services must only name configured services");
}
