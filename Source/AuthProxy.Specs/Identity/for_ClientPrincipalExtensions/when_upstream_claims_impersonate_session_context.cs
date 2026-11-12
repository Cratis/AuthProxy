// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.Identity.for_ClientPrincipalExtensions;

public class when_upstream_claims_impersonate_session_context : given.a_recorded_session
{
    [Theory]
    [InlineData(SessionClaims.Started)]
    [InlineData(SessionClaims.SignInProvider)]
    [InlineData("URN:CRATIS:SESSION:STARTED")]
    public void should_filter_upstream_claims_when_forwarding_is_off(string type)
    {
        ((ClaimsIdentity)_context.User.Identity!).AddClaim(new Claim(type, "forged"));
        _context.BuildClientPrincipal()!.Claims.Any(_ => SessionClaims.IsForwardedSessionContext(_.Type)).ShouldBeFalse();
    }
}
