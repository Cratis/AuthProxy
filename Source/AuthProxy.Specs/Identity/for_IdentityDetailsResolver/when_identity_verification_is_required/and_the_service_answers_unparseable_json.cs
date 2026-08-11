// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.Arc.Identity;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_verification_is_required;

/// <summary>
/// A body that will not parse is the classic shape of an intercepting proxy, a captive portal, or a load
/// balancer's own error page arriving at <c>200</c>. The released code caught the parse failure and carried
/// on with empty details, so an HTML sign-in page from somebody else's infrastructure authorized the caller.
/// </summary>
public class and_the_service_answers_unparseable_json : given.a_required_verification_resolver
{
    IdentityProviderResult _result;

    void Establish() => _handler.Respond = (_, _, _) => Task.FromResult(Response(HttpStatusCode.OK, "{not-json"));

    async Task Because() => _result = await _resolver.Resolve(_context, Principal(), TenantId);

    [Fact] void should_not_be_authorized() => _result.IsAuthorized.ShouldBeFalse();
    [Fact] void should_serve_the_forbidden_status() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status403Forbidden);
    [Fact] void should_clear_any_recorded_authorization() => _authorizationCache.Received(1).Clear(_context);
}
