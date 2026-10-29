// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// Specifies that a session recording no provider ends when several providers are configured.
/// </summary>
public class when_validating_a_legacy_cookie_ticket_without_a_recorded_provider_and_several_providers : canonical_cookie_registration
{
    (bool Accepted, string? SignedOutScheme) _result;

    async Task Because()
    {
        UseAuthentication(TwoProviderAuthentication());
        _result = await Validate(LegacyPrincipal(null), new AuthenticationProperties());
    }

    [Fact] void should_reject_the_ticket() => _result.Accepted.ShouldBeFalse();
    [Fact] void should_sign_out_the_cookie_scheme() => _result.SignedOutScheme.ShouldEqual(CookieAuthenticationDefaults.AuthenticationScheme);
}
