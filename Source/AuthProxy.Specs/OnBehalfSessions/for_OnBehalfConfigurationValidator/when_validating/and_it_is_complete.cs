// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.OnBehalfSessions.given;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfConfigurationValidator.when_validating;

public class and_it_is_complete : Specification
{
    ValidateOptionsResult _result;

    void Because() => _result = new OnBehalfConfigurationValidator().Validate(null, new OnBehalfConfiguration().Value);

    [Fact] void should_succeed() => _result.Succeeded.ShouldBeTrue();
}
