// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration.for_Service.when_resolving_the_verification_timeout;

/// <summary>
/// The other side of the same choice, and what makes the two modes genuinely different rather than one mode
/// with a flag. A service standing between a caller and a decision is bounded by default, because without a
/// bound one that accepts connections and then stops answering holds every authenticated request open for
/// the ambient hundred seconds — a refusal that never arrives is not fail-closed.
/// </summary>
public class and_a_required_service_states_none : Specification
{
    readonly C.Service _service = new()
    {
        Backend = new C.ServiceEndpoint { BaseUrl = "https://backend.example.com" },
        IdentityVerification = C.IdentityVerificationMode.Required
    };

    [Fact] void should_state_no_timeout() => _service.IdentityVerificationTimeout.ShouldBeNull();
    [Fact] void should_bound_the_wait_by_default() =>
        _service.EffectiveIdentityVerificationTimeout.ShouldEqual(C.Service.DefaultIdentityVerificationTimeout);
}
