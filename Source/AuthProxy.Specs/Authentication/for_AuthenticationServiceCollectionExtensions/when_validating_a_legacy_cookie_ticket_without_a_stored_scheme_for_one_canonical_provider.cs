// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// Specifies that a marker-free legacy session remains valid with one configured canonical provider.
/// </summary>
public class when_validating_a_legacy_cookie_ticket_without_a_stored_scheme_for_one_canonical_provider : canonical_cookie_registration
{
    (bool Accepted, string? SignedOutScheme) _result;

    async Task Because() => _result = await Validate(LegacyPrincipal(), new AuthenticationProperties());

    [Fact] void should_accept_the_ticket() => _result.Accepted.ShouldBeTrue();
    [Fact] void should_not_sign_out() => _result.SignedOutScheme.ShouldBeNull();
}
