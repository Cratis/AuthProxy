// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ApplicationContract.for_ApplicationContractTranslator;

public class when_a_provider_kind_is_unknown : given.contract_fixture
{
    Exception _error;

    void Establish() => _overrides[$"{ApplicationContractKeys.ProvidersKey}:0:Kind"] = "Facebook";

    async Task Because() => _error = await Catch.Exception(() =>
    {
        ApplicationContractTranslator.Translate(FromJson());
        return Task.CompletedTask;
    });

    [Fact] void should_name_the_kind() => _error.Message.ShouldContain("'Facebook'");
}
