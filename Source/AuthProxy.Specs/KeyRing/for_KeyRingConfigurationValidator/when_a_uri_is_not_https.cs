// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.KeyRing.for_KeyRingConfigurationValidator;

/// <summary>
/// A bearer token is not sent over plain http, so an http blob or vault address could never authenticate.
/// Saying so at startup beats a first request that fails inside the Azure SDK.
/// </summary>
public class when_a_uri_is_not_https : Specification
{
    ValidateOptionsResult _result;

    void Because() => _result = new KeyRingConfigurationValidator().Validate(null, new C.AuthProxy
    {
        DataProtection = new()
        {
            Store = C.DataProtectionStore.AzureBlob,
            AzureBlob = new() { BlobUri = "http://example.blob.core.windows.net/c/keys.xml" },
            KeyVault = new() { KeyIdentifier = "not a uri" },
        },
    });

    [Fact] void should_fail_once_per_setting() => _result.Failures.Count().ShouldEqual(2);
    [Fact] void should_name_the_blob_address() => _result.FailureMessage!.ShouldContain("http://example.blob.core.windows.net/c/keys.xml");
    [Fact] void should_name_the_vault_key() => _result.FailureMessage!.ShouldContain("not a uri");
}
