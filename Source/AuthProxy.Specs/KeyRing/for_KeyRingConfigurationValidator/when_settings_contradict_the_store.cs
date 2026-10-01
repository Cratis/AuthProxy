// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.KeyRing.for_KeyRingConfigurationValidator;

/// <summary>
/// A store setting that would be ignored is the case an operator cannot see: the proxy starts and each replica
/// keeps a key ring of its own. Each contradiction is named rather than resolved by picking a winner.
/// </summary>
public class when_settings_contradict_the_store : Specification
{
    ValidateOptionsResult _result;

    void Because() => _result = new KeyRingConfigurationValidator().Validate(null, new C.AuthProxy
    {
        DataProtectionKeysPath = "/mnt/keys",
        DataProtection = new()
        {
            Store = C.DataProtectionStore.Redis,
            Redis = new() { ConnectionString = "redis:6379" },
            AzureBlob = new() { BlobUri = "https://example.blob.core.windows.net/c/keys.xml" },
        },
    });

    [Fact] void should_fail_once_per_contradiction() => _result.Failures.Count().ShouldEqual(2);
    [Fact] void should_name_the_ignored_key_path() => _result.FailureMessage!.ShouldContain("DataProtectionKeysPath");
    [Fact] void should_name_the_ignored_blob_section() => _result.FailureMessage!.ShouldContain("DataProtection:AzureBlob");
}
