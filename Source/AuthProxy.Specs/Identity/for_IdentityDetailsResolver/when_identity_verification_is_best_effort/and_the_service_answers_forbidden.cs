// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.Arc.Identity;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_verification_is_best_effort;

/// <summary>
/// The other half of the fence, and the reason the default mode is not simply "admit everything": an HTTP
/// <c>403</c> is the one answer the released proxy refused on, and it still refuses on it. Without this the
/// pair of specs would read as though the default mode had no denial at all, and a later change removing the
/// last one would look like a simplification.
/// </summary>
public class and_the_service_answers_forbidden : given.a_best_effort_verification_resolver
{
    IdentityProviderResult _result;

    void Establish() => _handler.Respond = (_, _) => Task.FromResult(Response(HttpStatusCode.Forbidden));

    async Task Because() => _result = await _resolver.Resolve(_context, Principal(), TenantId);

    [Fact] void should_not_authorize_the_caller() => _result.IsAuthorized.ShouldBeFalse();
    [Fact] void should_serve_the_forbidden_status() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status403Forbidden);
    [Fact] void should_clear_the_recorded_authorization() => _authorizationCache.Received(1).Clear(_context);
}
