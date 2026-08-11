// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration.for_Service.when_resolving_the_verification_timeout;

/// <summary>
/// A bound on the wait is a property of fail-closed verification, not of enrichment. A service asked only
/// for details is asked on the terms it has always been asked on — the ambient client default — because
/// tightening it silently costs the caller those details rather than refusing anything, and nothing
/// downstream can tell a missing detail from a detail the service does not have.
/// </summary>
public class and_a_best_effort_service_states_none : Specification
{
    readonly C.Service _service = new()
    {
        Backend = new C.ServiceEndpoint { BaseUrl = "https://backend.example.com" }
    };

    [Fact] void should_state_no_timeout() => _service.IdentityVerificationTimeout.ShouldBeNull();
    [Fact] void should_leave_the_wait_unbounded() => _service.EffectiveIdentityVerificationTimeout.ShouldEqual(TimeSpan.Zero);
    [Fact] void should_not_apply_the_required_mode_default() =>
        (_service.EffectiveIdentityVerificationTimeout == C.Service.DefaultIdentityVerificationTimeout).ShouldBeFalse();
}
