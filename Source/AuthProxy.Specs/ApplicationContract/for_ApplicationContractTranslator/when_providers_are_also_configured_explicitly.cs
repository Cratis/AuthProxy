// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ApplicationContract.for_ApplicationContractTranslator;

public class when_providers_are_also_configured_explicitly : given.contract_fixture
{
    Exception _error;

    void Establish() => _overrides[$"{C.Authentication.SectionKey}:OidcProviders:0:Name"] = "Other";

    async Task Because() => _error = await Catch.Exception(() =>
    {
        ApplicationContractTranslator.Translate(FromJson());
        return Task.CompletedTask;
    });

    [Fact] void should_refuse_to_combine_them() => _error.ShouldBeOfExactType<ApplicationContractException>();
}
