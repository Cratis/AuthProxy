// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityForwardingGuardMiddleware;

public class when_proxied_route_is_anonymous : given.a_proxied_request
{
    void Establish() => SetProxyRoute("anonymous");

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_call_next() => _nextCalled.ShouldBeTrue();
    [Fact] void should_not_change_the_status_code() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status200OK);
}
