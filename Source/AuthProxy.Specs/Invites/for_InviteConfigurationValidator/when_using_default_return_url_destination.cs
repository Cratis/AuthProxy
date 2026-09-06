// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteConfigurationValidator;

public class when_using_default_return_url_destination : given.an_invite_configuration
{
    C.Invite _invite;
    ValidateOptionsResult _result;

    void Establish() => _invite = new C.Invite
    {
        ExchangeUrl = "https://lobby.example.com/_invite/exchange"
    };

    void Because() => _result = Validate(new C.AuthProxy { Invite = _invite });

    [Fact]
    void should_default_to_return_url() =>
        _invite.MatchingTenantInvitationDestination.ShouldEqual(C.InvitationCompletionDestination.ReturnUrl);

    [Fact]
    void should_succeed() => _result.Succeeded.ShouldBeTrue();
}
