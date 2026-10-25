// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeys.when_a_refresh_is_due;

public class and_it_succeeds : given.an_invitation_token_issuer
{
    async Task Establish()
    {
        await Get();
        Handler.Kid = "rotated";
        Clock.Advance(TimeSpan.FromMinutes(5));
    }
    async Task Because() => Keys = await Get(refresh: true);
    [Fact] void should_remove_the_revoked_key() => Keys!.ContainsKey("known").ShouldBeFalse();
    [Fact] void should_use_the_new_key() => Keys!["rotated"].KeyId.ShouldEqual("rotated");
    [Fact] void should_refetch_both_documents() => Handler.KeyRequests.ShouldEqual(2);
}
