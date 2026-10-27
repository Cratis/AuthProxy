// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_TenancyMiddleware.when_acting_on_behalf_of_somebody;

/// <summary>
/// A deployment listing its claim resolution first resolves the actor's own tenant before ever looking at the host.
/// The pin does not depend on that order: every resolution is evaluated, and any one addressing another tenant refuses.
/// </summary>
public class and_a_claim_resolution_listed_first_hides_a_host_addressing_another_tenant : given.an_on_behalf_request
{
    void Establish() => Resolves(
        new TenantResolutionResult(SessionTenant, C.TenantSourceIdentifierResolverType.Claim),
        new TenantResolutionResult("other-tenant", C.TenantSourceIdentifierResolverType.Host));

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_refuse_the_request() => _errorPages.Received(1).WriteErrorPageAsync(_context, WellKnownPageNames.Forbidden, StatusCodes.Status403Forbidden);
    [Fact] void should_not_forward_the_request() => _nextCalled.ShouldBeFalse();
}
