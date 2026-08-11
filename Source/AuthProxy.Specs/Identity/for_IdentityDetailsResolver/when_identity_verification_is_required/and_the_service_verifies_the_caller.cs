// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Arc.Identity;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_verification_is_required;

/// <summary>
/// The positive control. Fail-closed is only worth anything if the open case still opens: a service that
/// answers an unambiguous positive verdict admits the caller, enriches them, and has the authorization
/// remembered exactly as before.
/// </summary>
public class and_the_service_verifies_the_caller : given.a_required_verification_resolver
{
    IdentityProviderResult _result;

    async Task Because() => _result = await _resolver.Resolve(_context, Principal(), TenantId);

    [Fact] void should_be_authorized() => _result.IsAuthorized.ShouldBeTrue();
    [Fact] void should_write_the_identity_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain(Cookies.Identity);
    [Fact] void should_record_the_authorization() => _authorizationCache.Received(1).Record(_context, Arg.Any<ClientPrincipal>(), TenantId);
    [Fact] void should_not_clear_the_authorization() => _authorizationCache.DidNotReceive().Clear(Arg.Any<HttpContext>());
    [Fact] void should_leave_the_response_status_alone() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status200OK);
}
