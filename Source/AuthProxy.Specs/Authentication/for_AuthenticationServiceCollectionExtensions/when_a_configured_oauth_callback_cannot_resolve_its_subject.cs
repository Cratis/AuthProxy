// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;
using Cratis.AuthProxy.SignIns;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// Specifies that an unresolved canonical OAuth callback fails before normal sign-in side effects.
/// </summary>
public class when_a_configured_oauth_callback_cannot_resolve_its_subject : configured_canonical_provider_callbacks
{
    TicketReceivedContext _ticketContext;
    ISignInNotifier _notifier;

    async Task Because()
    {
        var context = Context();
        _notifier = _services.GetRequiredService<ISignInNotifier>();
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "wrong-subject-claim")], "github"));
        _ticketContext = TicketContext(context, "github", _oauthOptions, principal, new AuthenticationProperties());
        await _oauthOptions.Events.OnTicketReceived(_ticketContext);
    }

    [Fact] void should_fail_the_callback() => _ticketContext.Result.Failure.ShouldNotBeNull();
    [Fact] void should_not_apply_an_enriched_principal() => _ticketContext.Principal.FindFirst(CanonicalIdentityClaims.ProviderKey).ShouldBeNull();
    [Fact] void should_not_add_protocol_assurance() => _ticketContext.Principal.FindFirst("acr").ShouldBeNull();
    [Fact] void should_not_stamp_the_provider() => _ticketContext.Properties.Items.ContainsKey(AuthenticationServiceCollectionExtensions.AuthenticationSchemeStateKey).ShouldBeFalse();
    [Fact] void should_not_record_a_fingerprint() => _ticketContext.Properties.Items.ContainsKey(CanonicalSessionRegistrationFingerprint.StateKey).ShouldBeFalse();
    [Fact] async Task should_not_notify_sign_in() => await _notifier.DidNotReceive().Notify(Arg.Any<HttpContext>(), Arg.Any<ClaimsPrincipal?>(), Arg.Any<string?>());
}
