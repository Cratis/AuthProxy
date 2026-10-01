// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ActivityTimeoutConfigurationValidator;

public class when_a_lobby_has_no_timeouts : Specification
{
    ValidateOptionsResult _result;

    void Because() => _result = new ActivityTimeoutConfigurationValidator().Validate(
        null,
        new C.AuthProxy
        {
            ActivityTimeout = TimeSpan.FromMinutes(1),
            Invite = new C.Invite
            {
                Lobby = new C.Service
                {
                    Backend = new C.ServiceEndpoint { BaseUrl = "https://backend.local/" },
                    Frontend = new C.ServiceEndpoint { BaseUrl = "https://frontend.local/" },
                    Registration = new C.ServiceEndpoint { BaseUrl = "https://registration.local/" },
                },
            },
        });

    [Fact] void should_succeed() => _result.Succeeded.ShouldBeTrue();
}
