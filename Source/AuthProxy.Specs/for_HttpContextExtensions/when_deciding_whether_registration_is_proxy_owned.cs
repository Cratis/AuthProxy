// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;

namespace Cratis.AuthProxy.for_HttpContextExtensions;

/// <summary>
/// The registration flow ends by sending the signed-in user to the lobby's own registration page, served behind
/// the proxy at the same path. Treating that request as the proxy's cleared the route that forwards it, so nothing
/// answered it and the user was left on an empty page.
/// </summary>
public class when_deciding_whether_registration_is_proxy_owned : Specification
{
    bool _anonymous;
    bool _signedInWithRegistrationPending;
    bool _signedInWithNothingPending;
    bool _signedInOnAnInvitation;

    void Because()
    {
        _anonymous = Context("/register", signedIn: false, pending: false).IsProxyOwnedFlow();
        _signedInWithRegistrationPending = Context("/register", signedIn: true, pending: true).IsProxyOwnedFlow();
        _signedInWithNothingPending = Context("/register", signedIn: true, pending: false).IsProxyOwnedFlow();
        _signedInOnAnInvitation = Context("/invite/token", signedIn: true, pending: false).IsProxyOwnedFlow();
    }

    [Fact] void should_own_it_for_an_anonymous_caller() => _anonymous.ShouldBeTrue();
    [Fact] void should_own_it_while_a_registration_is_pending() => _signedInWithRegistrationPending.ShouldBeTrue();
    [Fact] void should_leave_it_to_the_lobby_for_a_signed_in_caller_with_nothing_pending() => _signedInWithNothingPending.ShouldBeFalse();
    [Fact] void should_still_own_an_invitation_for_a_signed_in_caller() => _signedInOnAnInvitation.ShouldBeTrue();

    static DefaultHttpContext Context(string path, bool signedIn, bool pending)
    {
        var context = new DefaultHttpContext();
        context.Request.Path = path;
        if (signedIn)
        {
            context.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "someone")], "test"));
        }

        if (pending)
        {
            context.Request.Headers.Cookie = $"{Cookies.Registration}=pending";
        }

        return context;
    }
}
