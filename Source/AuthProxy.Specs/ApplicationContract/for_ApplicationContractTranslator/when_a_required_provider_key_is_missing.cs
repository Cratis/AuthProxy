// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ApplicationContract.for_ApplicationContractTranslator;

public class when_a_required_provider_key_is_missing : given.missing_key
{
    public static TheoryData<string, string> Cases() => new()
    {
        { "EntraId", "tenantId" }, { "EntraId", "clientId" }, { "EntraId", "clientSecret" },
        { "GitHub", "clientId" }, { "GitHub", "clientSecret" },
        { "Google", "clientId" }, { "Google", "clientSecret" },
        { "Apple", "clientId" }, { "Apple", "clientSecret" },
        { "Partner", "authority" }, { "Partner", "clientId" }, { "Partner", "clientSecret" }
    };

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task should_fail_naming_the_key_and_the_provider(string identity, string key)
    {
        await Without(ApplicationContractKeys.ProviderValue(identity, key));
        _error.ShouldBeOfExactType<ApplicationContractException>();
        _error.Message.ShouldContain(ApplicationContractKeys.ProviderValue(identity, key));
        _error.Message.ShouldContain($"'{identity}'");
        _error.Message.ShouldContain("'development'");
    }

    [Fact]
    public async Task should_not_include_a_secret_value()
    {
        await Without(ApplicationContractKeys.ProviderValue("GitHub", "clientId"));
        _error.Message.ShouldNotContain("placeholder-github-client-secret");
    }
}
