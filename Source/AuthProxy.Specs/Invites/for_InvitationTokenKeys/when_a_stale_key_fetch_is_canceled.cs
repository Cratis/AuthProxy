// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationTokenKeys;

public class when_a_stale_key_fetch_is_canceled : given.an_invitation_token_issuer
{
    Exception? _failure;
    IReadOnlyDictionary<string, Microsoft.IdentityModel.Tokens.SecurityKey>? _immediateKeys;
    int _requestsBeforeRetry;

    async Task Establish()
    {
        await Get();
        Clock.Advance(InvitationTokenKeys.MaximumStaleness + TimeSpan.FromTicks(1));
        Handler.Delay = true;
    }

    async Task Because()
    {
        using var cancellation = new CancellationTokenSource();
        var fetching = Provider.GetSigningKeys(Invite, cancellation.Token);
        await Handler.Started.Task;
        await cancellation.CancelAsync();
        _failure = await ObserveFailure(fetching);
        Handler.Delay = false;
        _immediateKeys = await Get();
        await Get(refresh: true);
        Clock.Advance(InvitationTokenKeys.RequestedRefreshInterval - TimeSpan.FromTicks(1));
        await Get();
        _requestsBeforeRetry = Handler.MetadataRequests;
        Clock.Advance(TimeSpan.FromTicks(1));
        Keys = await Get();
    }

    [Fact] void should_propagate_caller_cancellation() => Assert.IsType<OperationCanceledException>(_failure, exactMatch: false);
    [Fact] void should_not_return_keys_older_than_twenty_four_hours() => _immediateKeys.ShouldBeNull();
    [Fact] void should_not_allow_missing_usable_keys_to_bypass_backoff() => _requestsBeforeRetry.ShouldEqual(2);
    [Fact] void should_retry_when_the_deadline_is_reached() => Handler.MetadataRequests.ShouldEqual(3);
    [Fact] void should_accept_fresh_keys_after_retrying() => Keys!["known"].KeyId.ShouldEqual("known");
}
