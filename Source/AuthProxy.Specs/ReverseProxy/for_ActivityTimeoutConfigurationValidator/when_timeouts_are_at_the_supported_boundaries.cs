// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ActivityTimeoutConfigurationValidator;

public class when_timeouts_are_at_the_supported_boundaries : Specification
{
    ValidateOptionsResult _result;

    void Because() => _result = new ActivityTimeoutConfigurationValidator().Validate(
        null,
        new C.AuthProxy
        {
            ActivityTimeout = TimeSpan.FromMilliseconds(1),
            Services = new Dictionary<string, C.Service>
            {
                ["App"] = new() { ActivityTimeout = TimeSpan.FromMilliseconds(int.MaxValue) },
            },
        });

    [Fact] void should_succeed() => _result.Succeeded.ShouldBeTrue();
}
