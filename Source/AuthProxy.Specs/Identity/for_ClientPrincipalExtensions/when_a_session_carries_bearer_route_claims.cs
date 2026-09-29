// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.BearerRoutes;

namespace Cratis.AuthProxy.Identity.for_ClientPrincipalExtensions;

/// <summary>
/// The <c language="text">urn:cratis:bearer:</c> claims tell a backend a request was authenticated on a bearer route, with
/// the scopes and client the token was validated for. A browser session's identity provider does not get to say
/// that, so those claims never reach the forwarded principal of a session.
/// </summary>
public class when_a_session_carries_bearer_route_claims : Specification
{
    DefaultHttpContext _context;
    ClientPrincipal? _result;

    void Establish()
    {
        _context = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim("sub", "subject-id"),
                new Claim(BearerRouteClaims.Scope, "direct:admin"),
                new Claim(BearerRouteClaims.ClientId, "trusted-client"),
            ],
            "cookie")),
        };
    }

    void Because() => _result = _context.BuildClientPrincipal();

    [Fact] void should_keep_the_session_claims() => Assert.Contains(_result!.Claims, _ => _.Type == "sub");
    [Fact] void should_not_forward_bearer_route_claims() => Assert.DoesNotContain(_result!.Claims, _ => BearerRouteClaims.IsReserved(_.Type));
}
