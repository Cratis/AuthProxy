// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Arc.Identity;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_verification_is_required;

/// <summary>
/// The way back. A service whose endpoint only enriches states <c language="text">BestEffort</c> and keeps the behavior
/// the default used to have: an unreachable service does not refuse the caller.
/// </summary>
public class and_the_service_opts_in_to_best_effort_and_cannot_be_reached : given.a_required_verification_resolver
{
    IdentityProviderResult _result;

    void Establish()
    {
        _config.Services["main"] = new C.Service
        {
            Backend = new C.ServiceEndpoint { BaseUrl = "https://backend.example.com" },
            IdentityVerification = C.IdentityVerificationMode.BestEffort
        };
        _handler.Respond = (_, _, _) => throw new HttpRequestException("connection refused");
    }

    async Task Because() => _result = await _resolver.Resolve(_context, Principal(), TenantId);

    [Fact] void should_still_admit_the_caller() => _result.IsAuthorized.ShouldBeTrue();
}
