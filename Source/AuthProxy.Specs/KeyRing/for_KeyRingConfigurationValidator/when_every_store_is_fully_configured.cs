// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.KeyRing.for_KeyRingConfigurationValidator;

public class when_every_store_is_fully_configured : Specification
{
    ValidateOptionsResult _blob;
    ValidateOptionsResult _redis;

    void Because()
    {
        _blob = new KeyRingConfigurationValidator().Validate(null, new C.AuthProxy
        {
            DataProtection = new()
            {
                Store = C.DataProtectionStore.AzureBlob,
                AzureBlob = new() { BlobUri = "https://example.blob.core.windows.net/c/keys.xml" },
                KeyVault = new() { KeyIdentifier = "https://example.vault.azure.net/keys/k" },
            },
        });

        _redis = new KeyRingConfigurationValidator().Validate(null, new C.AuthProxy
        {
            DataProtection = new() { Store = C.DataProtectionStore.Redis, Redis = new() { ConnectionString = "redis:6379" } },
        });
    }

    [Fact] void should_accept_azure_blob() => _blob.Succeeded.ShouldBeTrue();
    [Fact] void should_accept_redis() => _redis.Succeeded.ShouldBeTrue();
}
