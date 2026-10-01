// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens.for_AccessTokenConfigurationValidator;

public class when_the_access_token_names_an_audience : given.an_access_token_validator
{
    void Establish() => _service.AccessToken!.Provider = "workforce";

    void Because() => Validate();

    [Fact] void should_succeed() => _result.Succeeded.ShouldBeTrue();
}
