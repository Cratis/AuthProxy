// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ActivityTimeoutConfigurationValidator;

public class when_a_timeout_is_below_one_millisecond : Specification
{
    ValidateOptionsResult _result;

    void Because() => _result = new ActivityTimeoutConfigurationValidator().Validate(
        null,
        new C.AuthProxy { ActivityTimeout = TimeSpan.FromTicks(TimeSpan.TicksPerMillisecond / 2) });

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_the_setting() => _result.FailureMessage!.ShouldContain($"{C.AuthProxy.SectionKey}:ActivityTimeout ");
    [Fact] void should_explain_the_minimum() => _result.FailureMessage!.ShouldContain("less than one millisecond");
}
