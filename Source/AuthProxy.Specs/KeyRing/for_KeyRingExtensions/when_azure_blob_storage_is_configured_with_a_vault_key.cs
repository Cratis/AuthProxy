// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.KeyRing.for_KeyRingExtensions;

public class when_azure_blob_storage_is_configured_with_a_vault_key : given.a_key_ring_configuration
{
    protected override IDictionary<string, string?> Settings => new Dictionary<string, string?>
    {
        [$"{Section}:DataProtection:Store"] = "AzureBlob",
        [$"{Section}:DataProtection:AzureBlob:BlobUri"] = "https://example.blob.core.windows.net/dataprotection/keys.xml",
        [$"{Section}:DataProtection:KeyVault:KeyIdentifier"] = "https://example.vault.azure.net/keys/authproxy",
        [$"{Section}:DataProtection:ManagedIdentityClientId"] = "11111111-1111-1111-1111-111111111111",
    };

    void Because() => Build();

    [Fact] void should_persist_to_the_blob() => _options.XmlRepository.GetType().Name.ShouldEqual("AzureBlobXmlRepository");
    [Fact] void should_protect_the_keys_with_the_vault_key() => _options.XmlEncryptor.GetType().Name.ShouldEqual("AzureKeyVaultXmlEncryptor");
}
