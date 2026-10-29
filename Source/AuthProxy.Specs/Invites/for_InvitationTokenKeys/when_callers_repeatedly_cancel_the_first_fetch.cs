// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeys;

public class when_callers_repeatedly_cancel_the_first_fetch : given.an_invitation_token_issuer
{
    readonly List<Exception?> _failures = [];
    int _requestsBeforeCompletion;

    async Task Because()
    {
        Handler.Delay = true;
        for (var attempt = 0; attempt < 5; attempt++)
        {
            using var cancellation = new CancellationTokenSource();
            var fetching = Provider.GetSigningKeys(Invite, cancellation.Token, refresh: attempt % 2 == 0);
            await Handler.Started.Task;
            Clock.Advance(TimeSpan.FromSeconds(5));
            await cancellation.CancelAsync();
            _failures.Add(await ObserveFailure(fetching));
        }
        _requestsBeforeCompletion = Handler.MetadataRequests;
        Handler.Release.SetResult();
        Keys = await Get();
    }

    [Fact] void should_cancel_only_each_callers_wait() => Assert.All(_failures, failure => Assert.IsType<OperationCanceledException>(failure, exactMatch: false));
    [Fact] void should_share_one_download_across_every_canceled_wait() => _requestsBeforeCompletion.ShouldEqual(1);
    [Fact] void should_load_keys_despite_repeated_disconnects() => Keys!["known"].KeyId.ShouldEqual("known");
    [Fact] void should_not_start_a_replacement_download() => Handler.MetadataRequests.ShouldEqual(1);
    [Fact] void should_complete_one_jwks_request() => Handler.KeyRequests.ShouldEqual(1);
}
