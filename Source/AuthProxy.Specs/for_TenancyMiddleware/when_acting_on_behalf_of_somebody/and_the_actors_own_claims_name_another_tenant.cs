// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_TenancyMiddleware.when_acting_on_behalf_of_somebody;

/// <summary>
/// A tenant taken from the actor's own claims only says where the actor belongs. The session acts in the tenant its
/// grant was confirmed for.
/// </summary>
public class and_the_actors_own_claims_name_another_tenant : given.an_on_behalf_request
{
    void Establish() => Resolves("support-tenant", C.TenantSourceIdentifierResolverType.Claim);

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_act_in_the_sessions_tenant() => _context.Items[TenancyMiddleware.TenantIdItemKey].ShouldEqual(SessionTenant);
    [Fact] void should_forward_the_request() => _nextCalled.ShouldBeTrue();
}
