// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeys;

public class when_a_known_key_is_read_while_refreshing : given.an_invitation_token_issuer
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
        var refresh = Get(refresh: true);
        await Handler.Started.Task;
        var read = Get();
        _completedWithoutWaiting = read.IsCompletedSuccessfully;
        Handler.Release.SetResult();
        Keys = await read;
        await refresh;
    }
    [Fact] void should_not_wait_for_the_network() => _completedWithoutWaiting.ShouldBeTrue();
    [Fact] void should_use_last_good_keys() => Keys!["known"].KeyId.ShouldEqual("known");
}
