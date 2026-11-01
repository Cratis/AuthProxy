// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ApplicationContract.for_ApplicationContractTranslator;

public class when_a_secret_is_in_the_secrets_directory : given.contract_fixture
{
    IReadOnlyDictionary<string, string?> _translated;

    void Establish()
    {
        File.WriteAllText(Path.Combine(_secrets, "authentication.providers.Google.clientSecret"), "secret-from-directory\r\n");
        _overrides[$"{ApplicationContractKeys.EnvironmentKey}:authentication.providers.Google.clientSecret"] = null;
    }

    void Because() => _translated = ApplicationContractTranslator.Translate(FromJson());

    [Fact] void should_read_the_value_named_after_the_key() => _translated[$"{C.AuthProxy.SectionKey}:Authentication:OidcProviders:1:ClientSecret"].ShouldEqual("secret-from-directory");
}
