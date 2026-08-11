// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Invites.for_InvitationAuthenticationState.when_binding_a_pending_invitation;

/// <summary>
/// A deployment that has not enabled the attested protocol stages nothing, so there is no transaction to
/// bind — but the capability is still bound. It is what the provider returns with the session it
/// establishes, and the only evidence that session answered this invitation rather than predating it.
/// </summary>
public class and_nothing_was_staged : Specification
{
    const string Capability = "pending-capability";

    DefaultHttpContext _context;
    AuthenticationProperties _properties;
    bool _result;

    void Establish()
    {
        _context = new DefaultHttpContext();
        _context.Request.Headers.Cookie = $"{Cookies.InviteToken}={Capability}";
        _properties = new AuthenticationProperties();
    }

    void Because() => _result = InvitationAuthenticationState.TryBindPendingInvitation(_context, _properties);

    [Fact] void should_bind() => _result.ShouldBeTrue();
    [Fact]
    void should_bind_the_pending_capability() =>
        _properties.Items[InvitationAuthenticationState.CapabilityHashStateKey]
            .ShouldEqual(InvitationAuthenticationState.ComputeCapabilityHash(Capability));
}
