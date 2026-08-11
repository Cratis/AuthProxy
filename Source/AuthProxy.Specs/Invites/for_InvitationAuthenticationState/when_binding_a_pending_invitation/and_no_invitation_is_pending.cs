// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Invites.for_InvitationAuthenticationState.when_binding_a_pending_invitation;

/// <summary>
/// An ordinary sign-in has no invitation behind it, so nothing is added to the challenge — and it still
/// proceeds. Binding a capability here would attach invitation meaning to a session that has none.
/// </summary>
public class and_no_invitation_is_pending : Specification
{
    DefaultHttpContext _context;
    AuthenticationProperties _properties;
    bool _result;

    void Establish()
    {
        _context = new DefaultHttpContext();
        _properties = new AuthenticationProperties();
    }

    void Because() => _result = InvitationAuthenticationState.TryBindPendingInvitation(_context, _properties);

    [Fact] void should_allow_the_challenge() => _result.ShouldBeTrue();
    [Fact] void should_bind_nothing() => _properties.Items.ShouldBeEmpty();
}
