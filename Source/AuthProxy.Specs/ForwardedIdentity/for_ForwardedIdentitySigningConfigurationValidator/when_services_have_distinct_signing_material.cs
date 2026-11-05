// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigningConfigurationValidator;

public class when_services_have_distinct_signing_material : given.a_signing_configuration
{
    [Theory]
    [InlineData("spec-backend")]
    [InlineData("other-audience")]
    public void should_accept_independent_keys_even_with_the_same_key_id(string audience)
    {
        configuration.Services["other"] = new()
        {
            ForwardedIdentity = new()
            {
                Audience = audience,
                KeyId = settings.KeyId,
                SecretBase64 = Convert.ToBase64String(Enumerable.Repeat((byte)43, 32).ToArray())
            }
        };
        Validate();
        result.Succeeded.ShouldBeTrue();
    }
}
