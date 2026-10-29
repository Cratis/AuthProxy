// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Identity.for_InviteTokenClaimsPrincipalEnricher;

/// <summary>
/// Specifies that enrichment keeps the provider that names the principal's account.
/// </summary>
public class when_enriching_a_session_principal : Specification
{
    ClientPrincipal _result;

    void Because()
    {
        var validator = Substitute.For<IInviteTokenValidator>();
        validator.TryGetClaim("invite-token", "organization_id", out Arg.Any<string>())
            .Returns(callInfo =>
            {
                callInfo[2] = "org-123";
                return true;
            });
        var config = new C.AuthProxy
        {
            Invite = new C.Invite
            {
                ClaimsToForward = [new C.InviteClaimForwarding { FromClaimType = "organization_id" }]
            }
        };
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(config);

        var context = new DefaultHttpContext();
        context.Request.Headers.Cookie = $"{Cookies.InviteToken}=invite-token";
        var principal = new ClientPrincipal
        {
            IdentityProvider = "AuthenticationTypes.Federation",
            AccountProvider = "microsoft",
            UserId = "user-42"
        };

        _result = new InviteTokenClaimsPrincipalEnricher(validator, monitor).Enrich(context, principal);
    }

    [Fact] void should_add_the_invite_claim() => _result.Claims.Any(_ => _.Type == "organization_id").ShouldBeTrue();
    [Fact] void should_keep_the_account_provider() => _result.AccountProvider.ShouldEqual("microsoft");
}
