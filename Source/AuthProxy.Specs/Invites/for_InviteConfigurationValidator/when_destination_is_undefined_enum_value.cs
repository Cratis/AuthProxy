// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InviteConfigurationValidator;

public class when_destination_is_undefined_enum_value : given.an_invite_configuration
{
    ValidateOptionsResult _result;

    void Because() => _result = Validate(new C.AuthProxy
    {
        Invite = new C.Invite
        {
            ExchangeUrl = "https://lobby.example.com/_invite/exchange",
            MatchingTenantInvitationDestination = (C.InvitationCompletionDestination)99,
        }
    });

    [Fact]
    void should_fail() => _result.Failed.ShouldBeTrue();

    [Fact]
    void should_report_the_exact_failure() =>
        _result.Failures.ShouldContainOnly(
            ["Invite.MatchingTenantInvitationDestination has an undefined value '99'. Use 'ReturnUrl' or 'Lobby'."]);
}
