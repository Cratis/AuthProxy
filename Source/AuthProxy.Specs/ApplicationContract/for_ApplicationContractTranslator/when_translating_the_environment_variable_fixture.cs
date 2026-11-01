// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ApplicationContract.for_ApplicationContractTranslator;

public class when_translating_the_environment_variable_fixture : given.contract_fixture
{
    IReadOnlyDictionary<string, string?> _fromJson;
    IReadOnlyDictionary<string, string?> _fromEnvironment;

    void Because()
    {
        _fromJson = ApplicationContractTranslator.Translate(FromJson());
        _fromEnvironment = ApplicationContractTranslator.Translate(FromEnvironmentFile());
    }

    [Fact] void should_produce_the_same_number_of_settings() => _fromEnvironment.Count.ShouldEqual(_fromJson.Count);
    [Fact] void should_produce_the_same_settings() => _fromJson.All(_ => _fromEnvironment[_.Key] == _.Value).ShouldBeTrue();
}
