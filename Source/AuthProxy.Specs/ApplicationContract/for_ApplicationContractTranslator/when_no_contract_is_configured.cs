// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Configuration;

namespace Cratis.AuthProxy.ApplicationContract.for_ApplicationContractTranslator;

public class when_no_contract_is_configured : Specification
{
    IReadOnlyDictionary<string, string?> _translated;

    void Because() => _translated = ApplicationContractTranslator.Translate(new ConfigurationBuilder().Build());

    [Fact] void should_add_no_settings() => _translated.ShouldBeEmpty();
}
