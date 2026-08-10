// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

public class when_an_invitation_oauth_callback_derives_verified_email_and_canonical_identity : an_oauth_verified_email_callback
{
    TicketReceivedContext _ticketContext;

    async Task Because()
    {
        await InvokeCallback();
        _ticketContext = TicketContext(
            Context(),
            "github",
            _oauthOptions,
            _context.Principal!,
            _context.Properties);
        await _oauthOptions.Events.OnTicketReceived(_ticketContext);
    }

    [Fact] void should_preserve_the_verified_email() => _ticketContext.Principal!.Claims.Single(_ => _.Type == "email").Value.ShouldEqual("verified@example.com");
    [Fact] void should_preserve_the_verified_email_evidence() => _ticketContext.Principal!.Claims.Single(_ => _.Type == "email_verified").Value.ShouldEqual(bool.TrueString.ToLowerInvariant());
    [Fact] void should_preserve_provider_membership_enrichment() => _ticketContext.Principal!.Claims.Single(_ => _.Type == GitHubClaimTypes.Organization).Value.ShouldEqual("Cratis");
    [Fact] void should_enrich_the_canonical_provider() => _ticketContext.Principal!.FindFirst(CanonicalIdentityClaims.ProviderKey)!.Value.ShouldEqual("github-workforce");
    [Fact] void should_derive_protocol_assurance() => _ticketContext.Principal!.FindFirst("acr")!.Value.ShouldEqual("oauth");
}
