// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeys;

public class when_disposing_with_gate_waiters : given.an_invitation_token_issuer
{
    Exception?[] _waiterFailures;
    Exception? _fetchFailure;

    async Task Because()
    {
        Handler.Delay = true;
        Handler.HoldCancellation = true;
        var fetching = Get();
        await Handler.Started.Task;
        using var cancellation = new CancellationTokenSource();
        var waiters = Enumerable.Range(0, 4).Select(_ => Provider.GetSigningKeys(Invite, cancellation.Token)).ToArray();
        Provider.Dispose();
        try
        {
            await Handler.CancellationObserved.Task.WaitAsync(TimeSpan.FromSeconds(30), TimeProvider.System);
            _waiterFailures = await Task.WhenAll(waiters.Select(ObserveFailure)).WaitAsync(TimeSpan.FromSeconds(30), TimeProvider.System);
        }
        finally
        {
            await cancellation.CancelAsync();
            Handler.FinishCancellation.TrySetResult();
            _fetchFailure = await ObserveFailure(fetching);
        }
    }

    [Fact] void should_cancel_every_waiter_before_the_fetch_finishes() => Assert.All(_waiterFailures, failure => Assert.IsType<OperationCanceledException>(failure, exactMatch: false));
    [Fact] void should_preserve_the_gate_until_the_fetch_unwinds() => Assert.IsType<OperationCanceledException>(_fetchFailure, exactMatch: false);
    [Fact] void should_not_start_http_for_waiters() => Handler.MetadataRequests.ShouldEqual(1);
}
