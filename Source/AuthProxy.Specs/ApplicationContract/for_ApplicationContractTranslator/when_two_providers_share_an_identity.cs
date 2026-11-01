// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ApplicationContract.for_ApplicationContractTranslator;

public class when_two_providers_share_an_identity : given.contract_fixture
{
    Exception _error;

    void Establish() => _overrides[$"{ApplicationContractKeys.ProvidersKey}:4:Identity"] = "google";

    async Task Because() => _error = await Catch.Exception(() =>
    {
        ApplicationContractTranslator.Translate(FromJson());
        return Task.CompletedTask;
    });

    [Fact] void should_name_the_identity() => _error.Message.ShouldContain("'google'");
}
