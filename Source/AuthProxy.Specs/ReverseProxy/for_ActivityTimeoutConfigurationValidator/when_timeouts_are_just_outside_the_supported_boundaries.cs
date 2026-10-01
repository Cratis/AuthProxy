// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ActivityTimeoutConfigurationValidator;

public class when_timeouts_are_just_outside_the_supported_boundaries : Specification
{
    ValidateOptionsResult _result;

    void Because() => _result = new ActivityTimeoutConfigurationValidator().Validate(
        null,
        new C.AuthProxy
        {
            ActivityTimeout = TimeSpan.FromTicks(TimeSpan.TicksPerMillisecond - 1),
            Services = new Dictionary<string, C.Service>
            {
                ["App"] = new() { ActivityTimeout = TimeSpan.FromMilliseconds(int.MaxValue).Add(TimeSpan.FromTicks(1)) },
            },
        });

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_fail_once_per_offending_setting() => _result.Failures.Count().ShouldEqual(2);
}
