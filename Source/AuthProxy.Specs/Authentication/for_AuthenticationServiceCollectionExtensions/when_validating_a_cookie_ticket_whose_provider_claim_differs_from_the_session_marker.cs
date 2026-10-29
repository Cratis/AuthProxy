// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// Specifies that a claim disagreeing with the marker ends the session.
/// </summary>
public class when_validating_a_cookie_ticket_whose_provider_claim_differs_from_the_session_marker : canonical_cookie_registration
{
    (bool Accepted, string? SignedOutScheme) _result;

    async Task Because()
    {
        UseAuthentication(TwoProviderAuthentication());
        var principal = LegacyPrincipal("microsoft");
        _result = await Validate(principal, new AuthenticationProperties(new Dictionary<string, string?> { [SessionProvider.MarkerStateKey] = "github" }));
    }

    [Fact] void should_reject_the_ticket() => _result.Accepted.ShouldBeFalse();
    [Fact] void should_sign_out_the_cookie_scheme() => _result.SignedOutScheme.ShouldEqual(CookieAuthenticationDefaults.AuthenticationScheme);
}
