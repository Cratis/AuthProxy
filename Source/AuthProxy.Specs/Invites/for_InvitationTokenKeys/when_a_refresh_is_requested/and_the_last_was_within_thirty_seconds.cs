// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeys.when_a_refresh_is_requested;

public class and_the_last_was_within_thirty_seconds : given.an_invitation_token_issuer
{
    async Task Establish()
    {
        await Get(refresh: true);
        Clock.Advance(TimeSpan.FromSeconds(29));
    }
    async Task Because() => Keys = await Get(refresh: true);
    [Fact] void should_not_fetch_again() => Handler.MetadataRequests.ShouldEqual(1);
}
