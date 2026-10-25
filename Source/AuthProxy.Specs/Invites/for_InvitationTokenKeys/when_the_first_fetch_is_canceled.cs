// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeys;

public class when_the_first_fetch_is_canceled : given.an_invitation_token_issuer
{
    Exception? _failure;
    IReadOnlyDictionary<string, Microsoft.IdentityModel.Tokens.SecurityKey>? _immediateKeys;
    int _requestsBeforeRetry;

    async Task Because()
    {
        Handler.Delay = true;
        using var cancellation = new CancellationTokenSource();
        var fetching = Provider.GetSigningKeys(Invite, cancellation.Token);
        await Handler.Started.Task;
        await cancellation.CancelAsync();
        _failure = await ObserveFailure(fetching);
        Handler.Delay = false;
        _immediateKeys = await Get();
        await Get(refresh: true);
        Clock.Advance(InvitationTokenKeys.RequestedRefreshInterval - TimeSpan.FromTicks(1));
        await Get(refresh: true);
        _requestsBeforeRetry = Handler.MetadataRequests;
        Clock.Advance(TimeSpan.FromTicks(1));
        Keys = await Get();
    }

    [Fact] void should_propagate_caller_cancellation() => Assert.IsType<OperationCanceledException>(_failure, exactMatch: false);
    [Fact] void should_fail_closed_during_backoff() => _immediateKeys.ShouldBeNull();
    [Fact] void should_not_allow_normal_or_requested_calls_to_bypass_backoff() => _requestsBeforeRetry.ShouldEqual(1);
    [Fact] void should_retry_when_the_deadline_is_reached() => Handler.MetadataRequests.ShouldEqual(2);
    [Fact] void should_accept_keys_after_a_successful_retry() => Keys!["known"].KeyId.ShouldEqual("known");
}
