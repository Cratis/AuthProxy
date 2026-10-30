// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Security.for_InvitationBinding;

/// <summary>
///  The binding AuthProxy puts on the challenge for a pending invitation must come back in the properties of the
/// ticket the session cookie holds, because it is the only thing that tells a session established for that
/// invitation from one the browser was already carrying.
/// </summary>
/// <param name="harness">The running proxy with real OAuth and OpenID Connect providers.</param>
[Collection(InvitationBindingSpecCollection.Name)]
public class when_an_oauth_sign_in_answers_a_pending_invitation(InvitationBindingHarness harness) : IAsyncLifetime
{
    const string Capability = "pending-invitation-capability";

    AuthenticationProperties? _ticket;

    public async ValueTask InitializeAsync() =>
        _ticket = await harness.SignInForInvitation(SessionCookieHarness.ProviderScheme, Capability);

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact]
    public void should_issue_a_session() => Assert.NotNull(_ticket);

    [Fact]
    public void should_carry_the_invitation_binding_into_the_ticket() =>
        Assert.Equal(
            InvitationBindingHarness.ExpectedBinding(Capability),
            _ticket.Items[Invites.InvitationAuthenticationState.CapabilityHashStateKey]);
}
