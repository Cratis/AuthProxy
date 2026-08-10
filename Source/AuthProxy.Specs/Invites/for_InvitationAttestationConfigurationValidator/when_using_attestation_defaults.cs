// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationAttestationConfigurationValidator;

public class when_using_attestation_defaults : Specification
{
    C.InvitationAttestation _configuration;

    void Because() => _configuration = new C.InvitationAttestation();

    [Fact] void should_bound_the_lifetime_to_sixty_seconds() => _configuration.Lifetime.ShouldEqual(TimeSpan.FromSeconds(60));
}
