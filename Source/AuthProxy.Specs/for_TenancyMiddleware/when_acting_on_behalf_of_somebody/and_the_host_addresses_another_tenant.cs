// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_TenancyMiddleware.when_acting_on_behalf_of_somebody;

/// <summary>
/// A tenant taken from the request's address says where the request goes. An on-behalf session is never carried into a
/// tenant nobody granted.
/// </summary>
public class and_the_host_addresses_another_tenant : given.an_on_behalf_request
{
    void Establish() => Resolves("other-tenant", C.TenantSourceIdentifierResolverType.Host);

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_refuse_the_request() => _errorPages.Received(1).WriteErrorPageAsync(_context, WellKnownPageNames.Forbidden, StatusCodes.Status403Forbidden);
    [Fact] void should_not_forward_the_request() => _nextCalled.ShouldBeFalse();
    [Fact] void should_not_record_a_tenant() => _context.Items.ContainsKey(TenancyMiddleware.TenantIdItemKey).ShouldBeFalse();
}
