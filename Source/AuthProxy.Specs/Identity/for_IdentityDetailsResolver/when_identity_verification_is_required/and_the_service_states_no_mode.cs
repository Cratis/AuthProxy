// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Arc.Identity;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_verification_is_required;

/// <summary>
/// The behavior that changed with the default. A service that configures an identity endpoint and never
/// states a mode is asked for a decision, so an unreachable service refuses the caller instead of letting
/// them through. Pinned through the resolver, not only through the setting, because the default being right
/// on the property proves nothing if nothing reads it.
/// </summary>
public class and_the_service_states_no_mode : given.a_required_verification_resolver
{
    IdentityProviderResult _result;

    void Establish()
    {
        _config.Services["main"] = new C.Service
        {
            Backend = new C.ServiceEndpoint { BaseUrl = "https://backend.example.com" }
        };
        _handler.Respond = (_, _, _) => throw new HttpRequestException("connection refused");
    }

    async Task Because() => _result = await _resolver.Resolve(_context, Principal(), TenantId);

    [Fact] void should_name_the_service_and_its_compatibility_opt_out() => _logger.Text.ShouldContain("Cratis__AuthProxy__Services__main__IdentityVerification=BestEffort");
    [Fact] void should_not_be_authorized() => _result.IsAuthorized.ShouldBeFalse();
    [Fact] void should_serve_the_forbidden_status() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status403Forbidden);
    [Fact] void should_clear_any_recorded_authorization() => _authorizationCache.Received(1).Clear(_context);
}
