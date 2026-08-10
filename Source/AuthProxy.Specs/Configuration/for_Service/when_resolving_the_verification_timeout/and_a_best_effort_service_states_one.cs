// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration.for_Service.when_resolving_the_verification_timeout;

/// <summary>
/// The mode decides what an <em>unstated</em> timeout means. A stated one is a deployment's own decision and
/// is honored in either mode — otherwise a deployment that had bounded its enrichment calls on purpose would
/// find the setting quietly ignored.
/// </summary>
public class and_a_best_effort_service_states_one : Specification
{
    static readonly TimeSpan _stated = TimeSpan.FromSeconds(3);

    readonly C.Service _service = new()
    {
        Backend = new C.ServiceEndpoint { BaseUrl = "https://backend.example.com" },
        IdentityVerificationTimeout = _stated
    };

    [Fact] void should_honor_it() => _service.EffectiveIdentityVerificationTimeout.ShouldEqual(_stated);
}
