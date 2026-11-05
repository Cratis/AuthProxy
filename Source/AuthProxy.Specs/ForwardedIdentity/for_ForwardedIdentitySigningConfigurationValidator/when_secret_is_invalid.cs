// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigningConfigurationValidator;

public class when_secret_is_invalid : given.a_signing_configuration
{
    void Because() => Validate();
    [Theory]
    [InlineData("")]
    [InlineData("not-base64")]
    [InlineData("-_________________________________________8=")]
    [InlineData("KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio=\n")]
    public void should_reject_invalid_encodings(string secret)
    {
        settings.SecretBase64 = secret;
        Validate();
        result.Failed.ShouldBeTrue();
    }
    [Theory]
    [InlineData(31)]
    [InlineData(33)]
    public void should_reject_invalid_lengths(int length)
    {
        settings.SecretBase64 = Convert.ToBase64String(new byte[length]);
        Validate();
        result.Failed.ShouldBeTrue();
    }
}
