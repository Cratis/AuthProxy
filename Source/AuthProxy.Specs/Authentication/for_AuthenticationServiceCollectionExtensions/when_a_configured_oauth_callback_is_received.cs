// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// Specifies that a configured OAuth callback binds the explicit configured issuer.
/// </summary>
public class when_a_configured_oauth_callback_is_received : configured_canonical_provider_callbacks
{
    TicketReceivedContext _ticketContext;

    async Task Because()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("id", "github-subject")], "github"));
        _ticketContext = TicketContext(Context(), "github", _oauthOptions, principal, new AuthenticationProperties());
        await _oauthOptions.Events.OnTicketReceived(_ticketContext);
    }

    [Fact] void should_apply_the_enriched_principal() => _ticketContext.Principal!.FindFirst(CanonicalIdentityClaims.ProviderKey)!.Value.ShouldEqual("github-workforce");
    [Fact] void should_use_the_configured_issuer() => _ticketContext.Principal!.FindFirst(CanonicalIdentityClaims.Issuer)!.Value.ShouldEqual("https://github.example.com");
}
