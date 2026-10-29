// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeys;

public class when_max_age_is_below_the_floor : given.an_invitation_token_issuer
{
    async Task Establish()
    {
        Handler.MaxAge = TimeSpan.FromSeconds(1);
        await Get();
        Clock.Advance(TimeSpan.FromSeconds(59));
    }
    async Task Because() => Keys = await Get();
    [Fact] void should_not_refetch_yet() => Handler.MetadataRequests.ShouldEqual(1);
    [Fact] void should_keep_keys() => Keys!.Count.ShouldEqual(1);
}
