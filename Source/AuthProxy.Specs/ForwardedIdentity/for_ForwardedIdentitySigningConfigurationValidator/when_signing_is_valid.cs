// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigningConfigurationValidator;

public class when_signing_is_valid : given.a_signing_configuration
{
    void Because() => Validate();
    [Fact] void should_accept_the_configuration() => result.Succeeded.ShouldBeTrue();
}
