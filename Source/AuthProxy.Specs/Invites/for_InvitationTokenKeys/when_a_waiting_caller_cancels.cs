// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeys;

public class when_a_waiting_caller_cancels : given.an_invitation_token_issuer
{
    bool _cancelled;
    async Task Because()
    {
        Handler.Delay = true;
        var active = Get();
        await Handler.Started.Task;
        using var cancellation = new CancellationTokenSource();
        var waiting = Provider.GetSigningKeys(Invite, cancellation.Token);
        await cancellation.CancelAsync();
        try
        {
            await waiting;
        }
        catch (OperationCanceledException)
        {
            _cancelled = true;
        }
        Handler.Release.SetResult();
        await active;
        Keys = await Get();
    }
    [Fact] void should_cancel_the_waiting_request() => _cancelled.ShouldBeTrue();
    [Fact] void should_leave_the_gate_usable() => Keys!["known"].KeyId.ShouldEqual("known");
    [Fact] void should_not_cancel_the_shared_retrieval() => Handler.MetadataRequests.ShouldEqual(1);
}
