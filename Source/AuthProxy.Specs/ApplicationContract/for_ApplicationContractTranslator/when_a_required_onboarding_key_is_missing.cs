// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ApplicationContract.for_ApplicationContractTranslator;

public class when_a_required_onboarding_key_is_missing : given.missing_key
{
    public static TheoryData<string> Keys() => new()
    {
        "stageUrl", "exchangeUrl", "tokenMetadataUrl", "issuer", "audience", "lobbyFrontendBaseUrl",
        "attestation.issuer", "attestation.audience", "attestation.keyId"
    };

    [Theory]
    [MemberData(nameof(Keys))]
    public async Task should_fail_naming_the_key(string key)
    {
        await Without(ApplicationContractKeys.OnboardingValue(key));
        _error.ShouldBeOfExactType<ApplicationContractException>();
        _error.Message.ShouldContain(ApplicationContractKeys.OnboardingValue(key));
    }
}
