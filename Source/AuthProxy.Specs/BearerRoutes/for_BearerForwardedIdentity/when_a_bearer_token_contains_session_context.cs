// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerForwardedIdentity;

public class when_a_bearer_token_contains_session_context : Specification
{
    [Theory]
    [InlineData(SessionClaims.Started)]
    [InlineData(SessionClaims.SignInProvider)]
    [InlineData("URN:CRATIS:SESSION:STARTED")]
    public void should_drop_the_reserved_claim_without_dropping_other_claims(string reserved)
    {
        var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "client"), new Claim(reserved, "forged"), new Claim("scope", "read"), new Claim("auth_time", "1700000000")], "Bearer"));
        var config = new C.AuthProxy { Services = new Dictionary<string, C.Service> { ["app"] = new() { Backend = new() { BaseUrl = "https://backend.example.test" }, BearerRoutes = [new() { PathPrefix = "/api", Issuers = [new() { Issuer = "https://issuer.example.test" }], Audiences = ["backend"] }] } } };
        var principal = BearerForwardedIdentity.From(BearerTokenValidation.Success(user, "tenant"), BearerRouteTable.All(config).Single()).Principal;
        principal.Claims.Any(_ => SessionClaims.IsForwardedSessionContext(_.Type)).ShouldBeFalse();
        principal.Claims.Any(_ => _.Type == "scope").ShouldBeTrue();
        principal.Claims.Any(_ => _.Type == "auth_time").ShouldBeTrue();
    }
}
