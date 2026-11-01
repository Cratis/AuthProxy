// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ApplicationContract.for_ApplicationContractTranslator;

public class when_a_named_secret_file_is_missing : given.contract_fixture
{
    Exception _error;

    void Establish()
    {
        _overrides[$"{ApplicationContractKeys.EnvironmentKey}:authentication.providers.GitHub.clientSecret"] = null;
        _overrides[$"{ApplicationContractKeys.EnvironmentKey}:authentication.providers.GitHub.clientSecret{ApplicationContractKeys.FileSuffix}"] = Path.Combine(_secrets, "absent");
    }

    async Task Because() => _error = await Catch.Exception(() =>
    {
        ApplicationContractTranslator.Translate(FromJson());
        return Task.CompletedTask;
    });

    [Fact] void should_name_the_key() => _error.Message.ShouldContain("authentication.providers.GitHub.clientSecret");
    [Fact] void should_name_the_environment() => _error.Message.ShouldContain("'development'");
}
