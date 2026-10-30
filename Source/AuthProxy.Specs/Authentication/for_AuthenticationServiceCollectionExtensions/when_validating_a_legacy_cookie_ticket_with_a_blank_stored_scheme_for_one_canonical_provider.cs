// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// Specifies that a blank legacy scheme does not associate a marker-free session with the canonical provider.
/// </summary>
public class when_validating_a_legacy_cookie_ticket_with_a_blank_stored_scheme_for_one_canonical_provider : canonical_cookie_registration
{
    (bool Accepted, string? SignedOutScheme) _result;

    async Task Because()
    {
        var properties = new AuthenticationProperties();
        properties.Items[AuthenticationServiceCollectionExtensions.AuthenticationSchemeStateKey] = " ";
        _result = await Validate(LegacyPrincipal(), properties);
    }

    [Fact] void should_accept_the_ticket() => _result.Accepted.ShouldBeTrue();
    [Fact] void should_not_sign_out() => _result.SignedOutScheme.ShouldBeNull();
}
