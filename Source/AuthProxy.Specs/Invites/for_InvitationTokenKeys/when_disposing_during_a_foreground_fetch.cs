// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeys;

public class when_disposing_during_a_foreground_fetch : given.an_invitation_token_issuer
{
    Exception? _fetchFailure;
    Exception? _newRequestFailure;

    async Task Because()
    {
        Handler.Delay = true;
        Handler.HoldCancellation = true;
        var fetching = Get();
        await Handler.Started.Task;
        Provider.Dispose();
        await Handler.CancellationObserved.Task.WaitAsync(TimeSpan.FromSeconds(30), TimeProvider.System);
        _newRequestFailure = await ObserveFailure(Get());
        Handler.FinishCancellation.SetResult();
        _fetchFailure = await ObserveFailure(fetching);
        Provider.Dispose();
    }

    [Fact] void should_cancel_the_fetch_without_releasing_a_disposed_gate() => Assert.IsType<OperationCanceledException>(_fetchFailure, exactMatch: false);
    [Fact] void should_refuse_new_work_after_disposal() => Assert.IsType<ObjectDisposedException>(_newRequestFailure);
    [Fact] void should_not_start_another_http_request() => Handler.MetadataRequests.ShouldEqual(1);
}
