// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeys;

public class when_a_response_is_slower_than_the_timeout : given.an_invitation_token_issuer
{
    void Establish() => Handler.Delay = true;
    async Task Because() => Keys = await Get();
    [Fact] void should_fail_closed_without_throwing() => Keys.ShouldBeNull();
}
