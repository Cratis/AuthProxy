// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Arc.Identity;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_verification_is_required;

/// <summary>
/// The defect this whole mode exists for. A refused connection, a name that does not resolve, a TLS
/// handshake that fails — every one of them used to be caught and answered with an empty details object,
/// which the resolver then turned into a hard-coded authorized result and sealed into a cookie. The proxy
/// was at its most permissive precisely when it had learned the least.
/// </summary>
public class and_the_service_cannot_be_reached : given.a_required_verification_resolver
{
    IdentityProviderResult _result;

    void Establish() => _handler.Respond = (_, _, _) => throw new HttpRequestException("connection refused");

    async Task Because() => _result = await _resolver.Resolve(_context, Principal(), TenantId);

    [Fact] void should_not_be_authorized() => _result.IsAuthorized.ShouldBeFalse();
    [Fact] void should_serve_the_forbidden_status() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status403Forbidden);
    [Fact] void should_not_record_an_authorization() => _authorizationCache.DidNotReceive().Record(Arg.Any<HttpContext>(), Arg.Any<ClientPrincipal>(), Arg.Any<string>());
    [Fact] void should_clear_any_recorded_authorization() => _authorizationCache.Received(1).Clear(_context);
    [Fact] void should_expire_the_identity_cookie() => _context.Response.Headers.SetCookie.ToString().ShouldContain("expires=Thu, 01 Jan 1970");
}
