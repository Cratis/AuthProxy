// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_TenancyMiddleware.when_acting_on_behalf_of_somebody;

public class and_the_host_addresses_the_sessions_tenant : given.an_on_behalf_request
{
    void Establish() => Resolves("SESSION-TENANT", C.TenantSourceIdentifierResolverType.SubHost);

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_act_in_the_sessions_tenant() => _context.Items[TenancyMiddleware.TenantIdItemKey].ShouldEqual(SessionTenant);
    [Fact] void should_forward_the_request() => _nextCalled.ShouldBeTrue();
}
