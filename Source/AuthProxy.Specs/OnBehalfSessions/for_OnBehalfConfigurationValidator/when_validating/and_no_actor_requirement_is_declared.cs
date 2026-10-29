// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfConfigurationValidator.when_validating;

/// <summary>
/// A deployment must say who support is. Without a requirement any signed-in account could ask the application for a
/// grant, and the application would be the only thing between them and acting as somebody else.
/// </summary>
public class and_no_actor_requirement_is_declared : Specification
{
    ValidateOptionsResult _result;

    void Because()
    {
        var configuration = new OnBehalfConfiguration().Value;
        configuration.OnBehalf!.ActorAuthorization.RequiredClaims.Clear();
        _result = new OnBehalfConfigurationValidator().Validate(null, configuration);
    }

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_the_setting() => _result.FailureMessage.ShouldContain("OnBehalf.ActorAuthorization.RequiredClaims");
}
