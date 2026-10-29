// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_SessionProvider;

/// <summary>
/// Specifies that stamping removes every session claim a provider supplied, whatever its casing or identity.
/// </summary>
public class when_stamping_a_principal_that_already_carries_session_claims : Specification
{
    ClaimsPrincipal _principal;

    void Establish()
    {
        _principal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("sub", "user-42"), new Claim(SessionClaims.ProviderScheme, "github")],
            "AuthenticationTypes.Federation"));
        _principal.AddIdentity(new ClaimsIdentity([new Claim("URN:CRATIS:SESSION:other", "x")], "second"));
    }

    void Because() => SessionProvider.Stamp(_principal, new AuthenticationProperties(), "microsoft");

    [Fact] void should_leave_exactly_one_session_claim() => _principal.Claims.Count(_ => SessionClaims.IsReserved(_.Type)).ShouldEqual(1);
    [Fact] void should_record_the_scheme() => _principal.FindFirst(SessionClaims.ProviderScheme)!.Value.ShouldEqual("microsoft");
}
