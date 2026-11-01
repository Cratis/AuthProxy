// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ApplicationContract.for_ApplicationContractTranslator;

public class when_http_is_used_outside_development : given.contract_fixture
{
    Exception _error;

    void Establish() => _overrides[ApplicationContractKeys.DevelopmentKey] = "false";

    async Task Because() => _error = await Catch.Exception(() =>
    {
        ApplicationContractTranslator.Translate(FromJson());
        return Task.CompletedTask;
    });

    [Fact] void should_refuse_the_loopback_url() => _error.ShouldBeOfExactType<ApplicationContractException>();
    [Fact] void should_name_the_key() => _error.Message.ShouldContain("authentication.providers.Partner.authority");
}
