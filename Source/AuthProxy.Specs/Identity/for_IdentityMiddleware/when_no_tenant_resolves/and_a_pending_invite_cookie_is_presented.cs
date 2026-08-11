// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityMiddleware.when_no_tenant_resolves;

/// <summary>
/// The concrete route in a correctly configured deployment. A pending-invite cookie makes
/// <see cref="TenancyMiddleware"/> let a tenant-less request through so the onboarding exchange can run — and
/// when the exchange does not claim the request, which it does not for an ordinary application path, the
/// request carries on with no tenant and used to be forwarded with no verdict. The cookie is the caller's to
/// send, so this was a bypass anyone with a session could ask for by name.
/// </summary>
public class and_a_pending_invite_cookie_is_presented : given.an_identity_middleware
{
    void Establish() => _context.Request.Headers.Cookie = $"{Cookies.InviteToken}=pending-token";

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_refuse_the_request() => ShouldHaveBeenRefused();
    [Fact] void should_not_forward_the_request() => _nextCalled.ShouldBeFalse();
}
