// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.DataProtection.Repositories;

namespace Cratis.AuthProxy.KeyRing.for_KeyRingExtensions;

/// <summary>
/// Key protection is independent of where the key ring lives, so a shared volume does not have to hold it in
/// the clear.
/// </summary>
public class when_a_vault_key_protects_the_file_system_store : given.a_key_ring_configuration
{
    protected override IDictionary<string, string?> Settings => new Dictionary<string, string?>
    {
        [$"{Section}:DataProtectionKeysPath"] = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName()),
        [$"{Section}:DataProtection:KeyVault:KeyIdentifier"] = "https://example.vault.azure.net/keys/authproxy",
    };

    void Because() => Build();

    [Fact] void should_persist_to_the_directory() => _options.XmlRepository.ShouldBeOfExactType<FileSystemXmlRepository>();
    [Fact] void should_protect_the_keys_with_the_vault_key() => _options.XmlEncryptor.GetType().Name.ShouldEqual("AzureKeyVaultXmlEncryptor");
}
