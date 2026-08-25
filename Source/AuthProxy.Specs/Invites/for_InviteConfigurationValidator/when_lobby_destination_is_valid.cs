// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteConfigurationValidator;

public class when_lobby_destination_is_valid : given.an_invite_configuration
{
    ValidateOptionsResult _result;

    void Because() => _result = Validate(new C.AuthProxy
    {
        Invite = new C.Invite
        {
            ExchangeUrl = "https://lobby.example.com/_invite/exchange",
            TenantClaim = "tenant_id",
            MatchingTenantInvitationDestination = C.InvitationCompletionDestination.Lobby,
            Lobby = new C.Service
            {
                Frontend = new C.ServiceEndpoint { BaseUrl = "https://lobby.example.com/" }
            }
        }
    });

    [Fact]
    void should_succeed() => _result.Succeeded.ShouldBeTrue();
}
