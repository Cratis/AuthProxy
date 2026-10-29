// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeys;

public class when_an_automatic_refresh_is_due : given.an_invitation_token_issuer
{
    bool _completedWithoutWaiting;
    async Task Establish()
    {
        await Get();
        Handler.Delay = true;
        Clock.Advance(TimeSpan.FromMinutes(5));
    }
    async Task Because()
    {
        var read = Get();
        _completedWithoutWaiting = read.IsCompletedSuccessfully;
        Keys = await read;
        await Handler.Started.Task;
        Handler.Release.SetResult();
    }
    [Fact] void should_return_last_good_keys_immediately() => _completedWithoutWaiting.ShouldBeTrue();
    [Fact] void should_start_the_refresh_in_the_background() => Handler.MetadataRequests.ShouldEqual(2);
    [Fact] void should_keep_serving_the_known_key() => Keys!["known"].KeyId.ShouldEqual("known");
}
