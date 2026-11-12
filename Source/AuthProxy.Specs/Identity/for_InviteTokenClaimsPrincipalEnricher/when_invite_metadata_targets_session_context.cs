// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Identity.for_InviteTokenClaimsPrincipalEnricher;

public class when_invite_metadata_targets_session_context : Specification
{
    [Theory]
    [InlineData(SessionClaims.Started)]
    [InlineData(SessionClaims.SignInProvider)]
    [InlineData("URN:CRATIS:SESSION:STARTED")]
    public void should_ignore_reserved_targets_but_keep_ordinary_metadata(string target)
    {
        var validator = Substitute.For<IInviteTokenValidator>();
        validator.TryGetClaim("invite-token", "team", out Arg.Any<string>()).Returns(call =>
        {
            call[2] = "blue";
            return true;
        });
        var config = new C.AuthProxy
        {
            Invite = new C.Invite
            {
                ClaimsToForward = [new C.InviteClaimForwarding { FromClaimType = "team", ToClaimType = target }, new C.InviteClaimForwarding { FromClaimType = "team" }]
            }
        };
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(config);
        var context = new DefaultHttpContext();
        context.Request.Headers.Cookie = $"{Cookies.InviteToken}=invite-token";
        var principal = new ClientPrincipal { Claims = [] };
        var result = new InviteTokenClaimsPrincipalEnricher(validator, monitor).Enrich(context, principal);
        result.Claims.Any(_ => SessionClaims.IsForwardedSessionContext(_.Type)).ShouldBeFalse();
        result.Claims.Single().Value.ShouldEqual("blue");
    }
}
