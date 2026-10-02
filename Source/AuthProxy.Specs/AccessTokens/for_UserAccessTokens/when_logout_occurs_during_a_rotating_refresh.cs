// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.AccessTokens.given;

namespace Cratis.AuthProxy.AccessTokens.for_UserAccessTokens;

public class when_logout_occurs_during_a_rotating_refresh : given.user_access_tokens
{
    UserAccessTokenResult _result;
    UserAccessTokenResult _replayed;
    UserTokenSession? _session;

    async Task Because()
    {
        var issued = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var deliver = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _endpoint.AnswerAsync = async token =>
        {
            issued.SetResult();
            await deliver.Task.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System, token);
            return TokenEndpoint.Bearer("access-token", 3600, "rotated-refresh-token");
        };
        var request = Get();
        await issued.Task.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
        await _store.Remove(_sessionId, CancellationToken.None);
        deliver.SetResult();
        _result = await request.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
        _session = await _store.Get(_sessionId, CancellationToken.None);
        _replayed = await Get();
    }

    [Fact] void should_not_resurrect_the_session() => _session.ShouldBeNull();
    [Fact] void should_not_forward_the_in_flight_token() => _result.Failure.ShouldEqual(UserAccessTokenFailure.NoRefreshToken);
    [Fact] void should_refuse_a_replayed_cookie_session() => _replayed.Failure.ShouldEqual(UserAccessTokenFailure.NoRefreshToken);
    [Fact] void should_not_cache_the_access_token() => _cache.Written.Count.ShouldEqual(1);
}
