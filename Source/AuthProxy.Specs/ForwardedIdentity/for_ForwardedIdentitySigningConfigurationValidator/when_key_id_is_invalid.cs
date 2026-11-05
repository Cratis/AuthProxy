// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigningConfigurationValidator;

public class when_key_id_is_invalid : given.a_signing_configuration
{
    void Because() => Validate();
    [Theory]
    [InlineData("")]
    [InlineData("key id")]
    [InlineData("key+id")]
    [InlineData("\u00e9")]
    public void should_reject_invalid_key_ids(string keyId)
    {
        settings.KeyId = keyId;
        Validate();
        result.Failed.ShouldBeTrue();
    }
    [Fact]
    void should_reject_an_oversized_key_id()
    {
        settings.KeyId = new string('a', 65);
        Validate();
        result.Failed.ShouldBeTrue();
    }
}
