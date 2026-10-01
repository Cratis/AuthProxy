// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration.for_Service;

/// <summary>
/// Flipping the default must not turn a service that is never asked into one that denies. Fail-closed
/// applies to a service whose <c language="text">/.cratis/me</c> endpoint is called; a service with no backend, or one that
/// opted out of identity resolution, has no endpoint to fail, so it neither takes part nor makes the
/// deployment demand a verdict.
/// </summary>
public class when_a_service_has_no_identity_endpoint : Specification
{
    readonly C.AuthProxy _config = new()
    {
        Services = new Dictionary<string, C.Service>
        {
            ["frontend-only"] = new() { Frontend = new C.ServiceEndpoint { BaseUrl = "https://frontend.example.com" } },
            ["opted-out"] = new()
            {
                Backend = new C.ServiceEndpoint { BaseUrl = "https://backend.example.com" },
                ResolveIdentityDetails = false
            }
        }
    };

    [Fact] void should_not_ask_a_service_without_a_backend() => _config.Services["frontend-only"].ParticipatesInIdentityResolution.ShouldBeFalse();
    [Fact] void should_not_ask_a_service_that_opted_out() => _config.Services["opted-out"].ParticipatesInIdentityResolution.ShouldBeFalse();
    [Fact] void should_not_require_verification_for_the_deployment() => _config.RequiresIdentityVerification.ShouldBeFalse();
}
