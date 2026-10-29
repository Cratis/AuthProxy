// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// Specifies that a ticket carrying both the claim and AuthProxy's marker is trusted with several providers.
/// </summary>
public class when_validating_a_cookie_ticket_with_a_provider_claim_and_the_session_marker : canonical_cookie_registration
{
    (bool Accepted, string? SignedOutScheme) _result;

    async Task Because()
    {
        UseAuthentication(TwoProviderAuthentication());
        var principal = LegacyPrincipal("microsoft");
        _result = await Validate(principal, new AuthenticationProperties(new Dictionary<string, string?> { [SessionProvider.MarkerStateKey] = "microsoft" }));
    }

    [Fact] void should_accept_the_ticket() => _result.Accepted.ShouldBeTrue();
}
