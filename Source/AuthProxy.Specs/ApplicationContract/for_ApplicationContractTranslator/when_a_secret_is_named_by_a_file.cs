// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ApplicationContract.for_ApplicationContractTranslator;

public class when_a_secret_is_named_by_a_file : given.contract_fixture
{
    IReadOnlyDictionary<string, string?> _translated;

    void Establish()
    {
        File.WriteAllText(Path.Combine(_secrets, "github-secret"), "secret-from-file\n");
        _overrides[$"{ApplicationContractKeys.EnvironmentKey}:authentication.providers.GitHub.clientSecret"] = null;
        _overrides[$"{ApplicationContractKeys.EnvironmentKey}:authentication.providers.GitHub.clientSecret{ApplicationContractKeys.FileSuffix}"] = Path.Combine(_secrets, "github-secret");
    }

    void Because() => _translated = ApplicationContractTranslator.Translate(FromJson());

    [Fact] void should_read_the_value_from_the_file() => _translated[$"{C.AuthProxy.SectionKey}:Authentication:OAuthProviders:0:ClientSecret"].ShouldEqual("secret-from-file");
}
