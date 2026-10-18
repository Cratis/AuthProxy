// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator;

/// <summary>
/// An active key that names no configured key would leave every request unsignable, and so answered with 502.
/// </summary>
public class when_the_active_key_is_not_configured : given.a_signing_deployment
{
    void Establish() => _configuration.ForwardingAttestation!.ActiveKeyId = "next";

    void Because() => Validate();

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_the_active_key() => HasFailure("ForwardingAttestation.ActiveKeyId must identify exactly one configured signing key.").ShouldBeTrue();
}
