// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.Arc.Identity;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_verification_is_required;

/// <summary>
/// Denying is only half of fail-closed. The other half is that the denial has to survive contact with
/// everything an earlier success left behind — a sealed authorization record, a readable identity cookie,
/// and an in-memory result — because each of them is a way for the very next request to skip the question
/// that was just answered no.
/// <para>
/// A deployment that turns both memories off is asking to be re-verified on every request, and the released
/// code could not honor that: the in-memory duration was a hard-coded constant, and a zero re-validation
/// interval silently became the longest lifetime the setting can produce.
/// </para>
/// </summary>
public class and_a_success_is_followed_immediately_by_a_failure : given.a_required_verification_resolver
{
    DefaultHttpContext _failingContext;
    IdentityProviderResult _first;
    IdentityProviderResult _second;

    void Establish()
    {
        _config.Session.IdentityRevalidationInterval = TimeSpan.Zero;
        _config.Session.IdentityResultCacheDuration = TimeSpan.Zero;
        _failingContext = new DefaultHttpContext();
        _handler.Respond = (_, call, _) => Task.FromResult(call == 1
            ? Response(HttpStatusCode.OK, PositiveBody)
            : Response(HttpStatusCode.ServiceUnavailable, "down"));
    }

    async Task Because()
    {
        _first = await _resolver.Resolve(_context, Principal(), TenantId);
        _second = await _resolver.Resolve(_failingContext, Principal(), TenantId);
    }

    [Fact] void should_authorize_the_first_request() => _first.IsAuthorized.ShouldBeTrue();
    [Fact] void should_not_authorize_the_second_request() => _second.IsAuthorized.ShouldBeFalse();
    [Fact] void should_ask_the_service_again_rather_than_reuse_the_success() => _handler.Calls.ShouldEqual(2);
    [Fact] void should_clear_the_recorded_authorization() => _authorizationCache.Received(1).Clear(_failingContext);
    [Fact] void should_expire_the_identity_cookie() => _failingContext.Response.Headers.SetCookie.ToString().ShouldContain("expires=Thu, 01 Jan 1970");
    [Fact] void should_serve_the_forbidden_status() => _failingContext.Response.StatusCode.ShouldEqual(StatusCodes.Status403Forbidden);
}
