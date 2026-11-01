// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ApplicationContract.for_ApplicationContractTranslator;

public class when_http_is_used_on_a_non_loopback_host_in_development : given.contract_fixture
{
    Exception _error;

    void Establish() => _overrides[$"{ApplicationContractKeys.EnvironmentKey}:authentication.providers.Partner.authority"] = "http://idp.example.com/";

    async Task Because() => _error = await Catch.Exception(() =>
    {
        ApplicationContractTranslator.Translate(FromJson());
        return Task.CompletedTask;
    });

    [Fact] void should_refuse_the_url() => _error.ShouldBeOfExactType<ApplicationContractException>();
}
