// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeys;

public class when_many_requests_need_an_unknown_kid_refresh : given.an_invitation_token_issuer
{
    async Task Establish()
    {
        await Get();
        Handler.Delay = true;
        Clock.Advance(TimeSpan.FromSeconds(30));
    }
    async Task Because()
    {
        var requests = Enumerable.Range(0, 20).Select(_ => Get(refresh: true)).ToArray();
        await Handler.Started.Task;
        Handler.Release.SetResult();
        await Task.WhenAll(requests);
    }
    [Fact] void should_share_one_refresh() => Handler.MetadataRequests.ShouldEqual(2);
    [Fact] void should_fetch_jwks_only_once_more() => Handler.KeyRequests.ShouldEqual(2);
}
