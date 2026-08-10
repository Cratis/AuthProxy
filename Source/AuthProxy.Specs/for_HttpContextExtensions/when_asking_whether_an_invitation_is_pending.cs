// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_HttpContextExtensions;

/// <summary>
/// Every caller of this asks it in order to <em>relax</em> something on the grounds that an invite exchange
/// is about to run: the tenancy refusal, the provider-selection refusal, the identity caches. Answering on
/// the cookie's presence alone let a bare <c>Cookie: .cratis-invite=</c> buy all of that while
/// <see cref="HttpContextExtensions.TryGetPendingInvitationToken"/> — which is what actually runs the
/// exchange — rejected the same blank value. So the relaxations happened, the exchange did not, and the
/// cookie is the caller's to send.
/// </summary>
public class when_asking_whether_an_invitation_is_pending : Specification
{
    bool _withAToken;
    bool _withABlankValue;
    bool _withNoCookie;

    void Because()
    {
        _withAToken = Context($"{Cookies.InviteToken}=pending-token").HasPendingInvitation();
        _withABlankValue = Context($"{Cookies.InviteToken}=").HasPendingInvitation();
        _withNoCookie = Context(cookie: null).HasPendingInvitation();
    }

    [Fact] void should_recognize_a_token() => _withAToken.ShouldBeTrue();
    [Fact] void should_not_recognize_a_blank_value() => _withABlankValue.ShouldBeFalse();
    [Fact] void should_not_recognize_an_absent_cookie() => _withNoCookie.ShouldBeFalse();

    static DefaultHttpContext Context(string? cookie)
    {
        var context = new DefaultHttpContext();
        if (cookie is not null)
        {
            context.Request.Headers.Cookie = cookie;
        }

        return context;
    }
}
