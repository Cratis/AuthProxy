// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigningConfigurationValidator;

public class when_audience_is_invalid : given.a_signing_configuration
{
    void Because() => Validate();
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("app\u00e9")]
    [InlineData("app\n")]
    public void should_reject_invalid_audiences(string audience)
    {
        settings.Audience = audience;
        Validate();
        result.Failed.ShouldBeTrue();
    }
    [Fact]
    void should_reject_an_oversized_audience()
    {
        settings.Audience = new string('a', 129);
        Validate();
        result.Failed.ShouldBeTrue();
    }
}
