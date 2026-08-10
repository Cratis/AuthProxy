// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// Specifies that a marker-free legacy ticket cannot bypass continuity after its recorded scheme becomes canonical.
/// </summary>
public class when_validating_a_marker_free_legacy_cookie_ticket_for_a_canonical_provider : canonical_cookie_registration
{
    (bool Accepted, string? SignedOutScheme) _outcome;

    async Task Because()
    {
        var properties = new AuthenticationProperties();
        properties.Items[AuthenticationServiceCollectionExtensions.AuthenticationSchemeStateKey] = ProviderScheme;
        _outcome = await Validate(LegacyPrincipal(), properties);
    }

    [Fact] void should_reject_and_sign_out_from_the_cookie_scheme() =>
        _outcome.ShouldEqual((false, CookieAuthenticationDefaults.AuthenticationScheme));
}
