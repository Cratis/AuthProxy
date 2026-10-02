// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.AccessTokens.given;

namespace Cratis.AuthProxy.AccessTokens.for_UserAccessTokens;

public class when_concurrent_requests_receive_a_refresh_rejection : given.user_access_tokens
{
    UserAccessTokenResult[] _results;

    async Task Because()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _endpoint.AnswerAsync = async cancellationToken =>
        {
            entered.SetResult();
            await release.Task.WaitAsync(cancellationToken);
            return TokenEndpoint.Error("invalid_grant");
        };
        var first = Get();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
        var second = Get();
        release.SetResult();
        _results = await Task.WhenAll(first, second).WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
    }

    [Fact] void should_redeem_only_once() => _endpoint.Received.Count.ShouldEqual(1);
    [Fact] void should_refuse_both_requests() => _results.All(_ => _.Failure == UserAccessTokenFailure.RefreshTokenRejected).ShouldBeTrue();
}
