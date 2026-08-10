// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.Arc.Identity;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_verification_is_required;

/// <summary>
/// A service that accepts the connection and then never answers is the failure a fail-closed mode has to
/// survive without hanging. The call used to carry no cancellation at all and inherited the ambient
/// hundred-second client default, so every authenticated request waited a minute and a half and then was
/// admitted anyway.
/// </summary>
public class and_the_verification_times_out : given.a_required_verification_resolver
{
    IdentityProviderResult _result;

    void Establish()
    {
        _service.IdentityVerificationTimeout = TimeSpan.FromMilliseconds(50);
        _handler.Respond = async (_, _, token) =>
        {
            await Task.Delay(TimeSpan.FromSeconds(30), token);
            return Response(HttpStatusCode.OK, PositiveBody);
        };
    }

    async Task Because() => _result = await _resolver.Resolve(_context, Principal(), TenantId);

    [Fact] void should_not_be_authorized() => _result.IsAuthorized.ShouldBeFalse();
    [Fact] void should_serve_the_forbidden_status() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status403Forbidden);
    [Fact] void should_clear_any_recorded_authorization() => _authorizationCache.Received(1).Clear(_context);
}
