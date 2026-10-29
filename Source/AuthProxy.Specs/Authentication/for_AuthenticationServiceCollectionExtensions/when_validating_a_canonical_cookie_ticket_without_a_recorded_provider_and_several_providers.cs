// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// Specifies that the recorded provider rule does not apply to canonical sessions.
/// </summary>
public class when_validating_a_canonical_cookie_ticket_without_a_recorded_provider_and_several_providers : canonical_cookie_registration
{
    bool _result;

    async Task Because()
    {
        var properties = await IssueCanonicalTicket();
        UseAuthentication(new C.Authentication
        {
            OidcProviders = InitialAuthentication().OidcProviders,
            OAuthProviders = OAuthAuthentication().OAuthProviders
        });
        _result = await IsAccepted(CanonicalPrincipal(), properties);
    }

    [Fact] void should_accept_the_ticket() => _result.ShouldBeTrue();
}
