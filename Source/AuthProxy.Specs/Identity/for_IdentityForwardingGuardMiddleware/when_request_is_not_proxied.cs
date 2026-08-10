// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityForwardingGuardMiddleware;

public class when_request_is_not_proxied : given.a_proxied_request
{
    void Establish() => _context.SetEndpoint(null);

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_call_next() => _nextCalled.ShouldBeTrue();
}
