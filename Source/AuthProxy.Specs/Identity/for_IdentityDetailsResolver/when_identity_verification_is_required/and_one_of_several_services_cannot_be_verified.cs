// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.Arc.Identity;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_verification_is_required;

/// <summary>
/// Requirements are added together and never widened, exactly as service claim requirements compose. Where
/// several services are asked for a verdict, every one of them has to supply it — one service saying yes
/// cannot cover for another that said nothing, or a deployment could weaken its own gate by adding a
/// service to it.
/// </summary>
public class and_one_of_several_services_cannot_be_verified : given.a_required_verification_resolver
{
    const string UnreachableHost = "unreachable.example.com";

    IdentityProviderResult _result;

    void Establish()
    {
        _config.Services["other"] = new C.Service
        {
            Backend = new C.ServiceEndpoint { BaseUrl = $"https://{UnreachableHost}" },
            IdentityVerification = C.IdentityVerificationMode.Required
        };
        _handler.Respond = (request, _, _) => Task.FromResult(
            request.RequestUri!.Host == UnreachableHost
                ? Response(HttpStatusCode.ServiceUnavailable, "down")
                : Response(HttpStatusCode.OK, PositiveBody));
    }

    async Task Because() => _result = await _resolver.Resolve(_context, Principal(), TenantId);

    [Fact] void should_not_be_authorized() => _result.IsAuthorized.ShouldBeFalse();
    [Fact] void should_serve_the_forbidden_status() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status403Forbidden);
    [Fact] void should_not_record_an_authorization() => _authorizationCache.DidNotReceive().Record(Arg.Any<HttpContext>(), Arg.Any<ClientPrincipal>(), Arg.Any<string>());
}
