// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy.for_CredentialBindingConfigurationValidator;

public class when_validating : Specification
{
    [Theory]
    [InlineData("", "", true)]
    [InlineData("direct-api", "staging", true)]
    [InlineData("direct.api_1~", "production", true)]
    [InlineData(" direct-api", "staging", false)]
    [InlineData("direct-api", "staging ", false)]
    [InlineData("direct;api", "staging", false)]
    [InlineData("direct-api", "stage=one", false)]
    public void should_validate_trusted_identifiers_without_repairing_them(string resource, string environment, bool valid)
    {
        var options = new C.AuthProxy { CredentialBinding = new() { Resource = resource, Environment = environment } };
        var result = new CredentialBindingConfigurationValidator().Validate(null, options);
        result.Succeeded.ShouldEqual(valid);
        if (!valid) result.FailureMessage.ShouldContain($"{C.AuthProxy.SectionKey}:CredentialBinding:");
    }

    [Fact]
    public void should_reject_an_overlong_identifier()
    {
        var options = new C.AuthProxy { CredentialBinding = new() { Resource = new string('a', 257) } };
        new CredentialBindingConfigurationValidator().Validate(null, options).Failed.ShouldBeTrue();
    }
}
