// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeys;

public class when_a_stale_key_fetch_is_canceled : given.an_invitation_token_issuer
{
    Exception? _failure;
    bool _followingRequestWaited;

    async Task Establish()
    {
        await Get();
        Clock.Advance(InvitationTokenKeys.MaximumStaleness + TimeSpan.FromTicks(1));
        Handler.Kid = "rotated";
        Handler.Delay = true;
    }

    async Task Because()
    {
        using var cancellation = new CancellationTokenSource();
        var fetching = Provider.GetSigningKeys(Invite, cancellation.Token);
        await Handler.Started.Task;
        await cancellation.CancelAsync();
        _failure = await ObserveFailure(fetching);
        var following = Get();
        _followingRequestWaited = !following.IsCompleted;
        Handler.Release.SetResult();
        Keys = await following;
    }

    [Fact] void should_propagate_caller_cancellation() => Assert.IsType<OperationCanceledException>(_failure, exactMatch: false);
    [Fact] void should_wait_for_fresh_keys_instead_of_returning_stale_keys() => _followingRequestWaited.ShouldBeTrue();
    [Fact] void should_accept_fresh_keys_from_the_original_download() => Keys!["rotated"].KeyId.ShouldEqual("rotated");
    [Fact] void should_not_start_a_replacement_download() => Handler.MetadataRequests.ShouldEqual(2);
    [Fact] void should_finish_the_original_jwks_download() => Handler.KeyRequests.ShouldEqual(2);
}
