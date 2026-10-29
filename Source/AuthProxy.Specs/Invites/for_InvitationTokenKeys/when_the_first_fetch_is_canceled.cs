// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeys;

public class when_the_first_fetch_is_canceled : given.an_invitation_token_issuer
{
    Exception? _failure;
    int _requestsBeforeCompletion;

    async Task Because()
    {
        Handler.Delay = true;
        using var cancellation = new CancellationTokenSource();
        var fetching = Provider.GetSigningKeys(Invite, cancellation.Token);
        await Handler.Started.Task;
        await cancellation.CancelAsync();
        _failure = await ObserveFailure(fetching);
        _requestsBeforeCompletion = Handler.MetadataRequests;
        Handler.Release.SetResult();
        Keys = await Get();
        await Get();
    }

    [Fact] void should_propagate_caller_cancellation() => Assert.IsType<OperationCanceledException>(_failure, exactMatch: false);
    [Fact] void should_leave_one_download_running_without_waiters() => _requestsBeforeCompletion.ShouldEqual(1);
    [Fact] void should_load_keys_without_waiting_for_a_retry_window() => Keys!["known"].KeyId.ShouldEqual("known");
    [Fact] void should_not_fetch_again_for_the_following_request() => Handler.MetadataRequests.ShouldEqual(1);
    [Fact] void should_complete_the_original_jwks_download() => Handler.KeyRequests.ShouldEqual(1);
}
