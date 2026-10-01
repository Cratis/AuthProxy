// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration.for_Service;

/// <summary>
/// The default for a service that says nothing about what its identity answer is worth. It used to be
/// <see cref="IdentityVerificationMode.BestEffort"/>, which lets a caller through when the identity service
/// is down, slow or answers nonsense — fail-open, for every deployment that never read the setting. A
/// secure default has to be the one nobody has to opt into.
/// </summary>
public class when_no_identity_verification_mode_is_stated : Specification
{
    readonly C.Service _service = new()
    {
        Backend = new C.ServiceEndpoint { BaseUrl = "https://backend.example.com" }
    };

    readonly C.AuthProxy _config = new();

    void Establish() => _config.Services = new Dictionary<string, C.Service> { ["main"] = _service };

    [Fact] void should_require_verification() => _service.IdentityVerification.ShouldEqual(IdentityVerificationMode.Required);
    [Fact] void should_take_part_in_identity_resolution() => _service.ParticipatesInIdentityResolution.ShouldBeTrue();
    [Fact] void should_make_the_deployment_require_verification() => _config.RequiresIdentityVerification.ShouldBeTrue();
}
