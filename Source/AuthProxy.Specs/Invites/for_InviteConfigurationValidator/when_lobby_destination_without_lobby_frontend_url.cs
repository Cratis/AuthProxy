// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteConfigurationValidator;

public class when_lobby_destination_without_lobby_frontend_url : given.an_invite_configuration
{
    ValidateOptionsResult _result;

    void Because() => _result = Validate(new C.AuthProxy
    {
        Invite = new C.Invite
        {
            ExchangeUrl = "https://lobby.example.com/_invite/exchange",
            TenantClaim = "tenant_id",
            MatchingTenantInvitationDestination = C.InvitationCompletionDestination.Lobby,
            Lobby = null
        }
    });

    [Fact]
    void should_fail() => _result.Failed.ShouldBeTrue();

    [Fact]
    void should_report_the_exact_failure() =>
        _result.Failures.ShouldContainOnly(
            [
                "Invite.MatchingTenantInvitationDestination is 'Lobby' but Invite.Lobby.Frontend.BaseUrl is not configured. " +
                "A Lobby frontend URL is required when matching-tenant invitations redirect to Lobby."
            ]);
}
