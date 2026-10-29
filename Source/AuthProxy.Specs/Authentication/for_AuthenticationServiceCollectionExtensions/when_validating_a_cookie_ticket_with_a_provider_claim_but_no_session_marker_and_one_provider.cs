// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// Specifies that an unmarked provider claim counts as no recorded provider and continues with one provider.
/// </summary>
public class when_validating_a_cookie_ticket_with_a_provider_claim_but_no_session_marker_and_one_provider : canonical_cookie_registration
{
    (bool Accepted, string? SignedOutScheme) _result;

    async Task Because()
    {
        UseAuthentication(InitialAuthentication(subjectClaimType: "sub"));
        var principal = LegacyPrincipal("microsoft");
        _result = await Validate(principal, new AuthenticationProperties());
    }

    [Fact] void should_accept_the_ticket() => _result.Accepted.ShouldBeTrue();
}
