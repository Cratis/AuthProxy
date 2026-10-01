// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ActivityTimeoutConfigurationValidator;

public class when_every_timeout_is_positive : Specification
{
    ValidateOptionsResult _result;

    void Because() => _result = new ActivityTimeoutConfigurationValidator().Validate(
        null,
        new C.AuthProxy
        {
            ActivityTimeout = TimeSpan.FromMinutes(10),
            Services = new Dictionary<string, C.Service>
            {
                ["App"] = new()
                {
                    ActivityTimeout = TimeSpan.FromHours(1),
                    Backend = new C.ServiceEndpoint { BaseUrl = "https://backend.local/", ActivityTimeout = TimeSpan.FromHours(24) },
                },
            },
        });

    [Fact] void should_succeed() => _result.Succeeded.ShouldBeTrue();
}
