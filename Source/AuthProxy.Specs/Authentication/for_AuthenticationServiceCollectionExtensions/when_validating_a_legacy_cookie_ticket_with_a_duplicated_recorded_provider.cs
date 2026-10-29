// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// Specifies that a session with a duplicated provider record ends.
/// </summary>
public class when_validating_a_legacy_cookie_ticket_with_a_duplicated_recorded_provider : canonical_cookie_registration
{
    (bool Accepted, string? SignedOutScheme) _result;

    async Task Because()
    {
        var principal = LegacyPrincipal("microsoft");
        principal.Identities.First().AddClaim(new Claim(SessionClaims.ProviderScheme, "github"));
        _result = await Validate(principal, new AuthenticationProperties());
    }

    [Fact] void should_reject_the_ticket() => _result.Accepted.ShouldBeFalse();
    [Fact] void should_sign_out_the_cookie_scheme() => _result.SignedOutScheme.ShouldEqual(CookieAuthenticationDefaults.AuthenticationScheme);
}
