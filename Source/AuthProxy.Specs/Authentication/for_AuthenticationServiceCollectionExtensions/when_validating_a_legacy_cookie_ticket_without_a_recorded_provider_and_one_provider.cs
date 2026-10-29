// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// Specifies that a session recording no provider continues when one provider is configured.
/// </summary>
public class when_validating_a_legacy_cookie_ticket_without_a_recorded_provider_and_one_provider : canonical_cookie_registration
{
    (bool Accepted, string? SignedOutScheme) _result;

    async Task Because()
    {
        UseAuthentication(InitialAuthentication(subjectClaimType: "sub"));
        _result = await Validate(LegacyPrincipal(null), new AuthenticationProperties());
    }

    [Fact] void should_accept_the_ticket() => _result.Accepted.ShouldBeTrue();
}
