// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfConfigurationValidator.when_validating;

public class and_it_is_not_configured : Specification
{
    ValidateOptionsResult _result;

    void Because() => _result = new OnBehalfConfigurationValidator().Validate(null, new C.AuthProxy());

    [Fact] void should_succeed() => _result.Succeeded.ShouldBeTrue();
}
