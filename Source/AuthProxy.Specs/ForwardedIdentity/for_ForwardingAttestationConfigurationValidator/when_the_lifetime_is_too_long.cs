// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator;

/// <summary>
/// A long-lived assertion widens the window in which a captured one can be replayed, so the lifetime is capped.
/// </summary>
public class when_the_lifetime_is_too_long : given.a_signing_deployment
{
    void Establish() => _configuration.ForwardingAttestation!.Lifetime = TimeSpan.FromSeconds(61);

    void Because() => Validate();

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_the_lifetime() => HasFailure("ForwardingAttestation.Lifetime must be between 10 and 60 seconds.").ShouldBeTrue();
}
