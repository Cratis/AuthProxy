// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeys;

public class when_max_age_is_above_the_ceiling : given.an_invitation_token_issuer
{
    async Task Establish()
    {
        Handler.MaxAge = TimeSpan.FromDays(2);
        await Get();
        Clock.Advance(TimeSpan.FromHours(12));
    }
    async Task Because() => Keys = await Get(refresh: true);
    [Fact] void should_refetch_at_twelve_hours() => Handler.MetadataRequests.ShouldEqual(2);
}
