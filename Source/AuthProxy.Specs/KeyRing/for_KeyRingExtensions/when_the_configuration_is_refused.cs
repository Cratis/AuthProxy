// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.KeyRing.for_KeyRingExtensions;

/// <summary>
/// A configuration the validator refuses is not half-applied: the host is stopped with the reason, and until
/// then nothing is persisted anywhere the operator did not ask for.
/// </summary>
public class when_the_configuration_is_refused : given.a_key_ring_configuration
{
    protected override IDictionary<string, string?> Settings => new Dictionary<string, string?>
    {
        [$"{Section}:DataProtection:Store"] = "AzureBlob",
        [$"{Section}:DataProtection:KeyVault:KeyIdentifier"] = "https://example.vault.azure.net/keys/authproxy",
    };

    void Because() => Build();

    [Fact] void should_not_persist_anywhere() => _options.XmlRepository.ShouldBeNull();
    [Fact] void should_not_protect_the_keys() => _options.XmlEncryptor.ShouldBeNull();
}
