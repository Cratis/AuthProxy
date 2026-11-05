// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigningConfigurationValidator;

public class when_services_reuse_signing_material : given.a_signing_configuration
{
    [Theory]
    [InlineData("spec-backend", "active-1")]
    [InlineData("other-audience", "different-key-id")]
    public void should_refuse_shared_material_and_name_only_the_two_paths(string audience, string keyId)
    {
        configuration.Services["other"] = new()
        {
            ForwardedIdentity = new() { Audience = audience, KeyId = keyId, SecretBase64 = settings.SecretBase64 }
        };
        Validate();
        result.Failed.ShouldBeTrue();
        result.Failures.Single().ShouldEqual($"{C.AuthProxy.SectionKey}:Services:main:ForwardedIdentity; {C.AuthProxy.SectionKey}:Services:other:ForwardedIdentity");
    }

    [Fact]
    void should_not_treat_two_service_entries_at_the_same_url_as_one_application()
    {
        configuration.Services["main"].Backend = new() { BaseUrl = "https://backend.test/app" };
        configuration.Services["other"] = new()
        {
            Backend = new() { BaseUrl = "https://backend.test/app" },
            ForwardedIdentity = settings
        };
        Validate();
        result.Failed.ShouldBeTrue();
    }
}
