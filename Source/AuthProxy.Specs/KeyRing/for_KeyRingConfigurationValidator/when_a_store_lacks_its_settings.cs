// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.KeyRing.for_KeyRingConfigurationValidator;

public class when_a_store_lacks_its_settings : Specification
{
    ValidateOptionsResult _blob;
    ValidateOptionsResult _redis;

    void Because()
    {
        _blob = new KeyRingConfigurationValidator().Validate(null, new C.AuthProxy { DataProtection = new() { Store = C.DataProtectionStore.AzureBlob } });
        _redis = new KeyRingConfigurationValidator().Validate(null, new C.AuthProxy { DataProtection = new() { Store = C.DataProtectionStore.Redis, Redis = new() } });
    }

    [Fact] void should_refuse_a_blob_store_without_a_blob() => _blob.Failed.ShouldBeTrue();
    [Fact] void should_name_the_blob_setting() => _blob.FailureMessage!.ShouldContain("DataProtection:AzureBlob:BlobUri");
    [Fact] void should_refuse_a_redis_store_without_a_connection_string() => _redis.Failed.ShouldBeTrue();
    [Fact] void should_name_the_connection_string_setting() => _redis.FailureMessage!.ShouldContain("DataProtection:Redis:ConnectionString");
}
