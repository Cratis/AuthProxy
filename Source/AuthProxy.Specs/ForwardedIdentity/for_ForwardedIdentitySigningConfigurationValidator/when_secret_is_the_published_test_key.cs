// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigningConfigurationValidator;

public class when_secret_is_the_published_test_key : given.a_signing_configuration
{
    void Establish() => settings.SecretBase64 = Convert.ToBase64String(Enumerable.Range(0, 32).Select(value => (byte)value).ToArray());
    void Because() => Validate();
    [Fact] void should_refuse_the_public_fixture() => result.Failed.ShouldBeTrue();
    [Fact] void should_not_include_secret_material() => result.FailureMessage.ShouldNotContain(settings.SecretBase64);
}
