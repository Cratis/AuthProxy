// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeys;

public class when_disposing_during_a_requested_refresh : given.an_invitation_token_issuer
{
    Exception? _refreshFailure;

    async Task Establish()
    {
        await Get();
        Clock.Advance(InvitationTokenKeys.RequestedRefreshInterval);
        Handler.Delay = true;
        Handler.HoldCancellation = true;
    }

    async Task Because()
    {
        var refreshing = Get(refresh: true);
        await Handler.Started.Task;
        Provider.Dispose();
        await Handler.CancellationObserved.Task.WaitAsync(TimeSpan.FromSeconds(30), TimeProvider.System);
        Handler.FinishCancellation.SetResult();
        _refreshFailure = await ObserveFailure(refreshing);
    }

    [Fact] void should_cancel_the_refresh_without_releasing_a_disposed_gate() => Assert.IsType<OperationCanceledException>(_refreshFailure, exactMatch: false);
}
