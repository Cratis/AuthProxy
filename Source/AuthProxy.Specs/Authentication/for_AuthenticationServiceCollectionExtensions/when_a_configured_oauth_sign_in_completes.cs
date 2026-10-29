// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// Specifies that a completed OAuth sign-in records its provider scheme on the session.
/// </summary>
public class when_a_configured_oauth_sign_in_completes : configured_canonical_provider_callbacks
{
    TicketReceivedContext _ticketContext;

    async Task Because()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("id", "github-subject")], "github"));
        _ticketContext = TicketContext(Context(), "github", _oauthOptions, principal, new AuthenticationProperties());
        await _oauthOptions.Events.OnTicketReceived(_ticketContext);
    }

    [Fact] void should_record_exactly_one_provider_scheme() => _ticketContext.Principal!.FindAll(SessionClaims.ProviderScheme).Count().ShouldEqual(1);
    [Fact] void should_record_the_oauth_scheme() => _ticketContext.Principal!.FindFirst(SessionClaims.ProviderScheme)!.Value.ShouldEqual("github");
}
