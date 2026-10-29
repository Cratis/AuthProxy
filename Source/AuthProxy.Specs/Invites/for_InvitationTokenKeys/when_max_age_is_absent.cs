// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeys;

public class when_max_age_is_absent : given.an_invitation_token_issuer
{
    int _beforeDeadline;
    async Task Because()
    {
        Handler.MaxAge = null;
        await Get();
        Clock.Advance(TimeSpan.FromHours(12) - TimeSpan.FromSeconds(1));
        await Get();
        _beforeDeadline = Handler.MetadataRequests;
        Clock.Advance(TimeSpan.FromSeconds(1));
        Keys = await Get(refresh: true);
    }
    [Fact] void should_not_refetch_before_twelve_hours() => _beforeDeadline.ShouldEqual(1);
    [Fact] void should_refetch_at_twelve_hours() => Handler.MetadataRequests.ShouldEqual(2);
}
