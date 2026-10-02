// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens.for_UserTokenStore;

public class when_logout_races_with_an_access_token_write : given.a_user_token_store
{
    UserTokenSession? _session;
    byte[]? _remainingToken;

    async Task Because()
    {
        var sessionId = await _store.Create(new("workforce", "refresh-token"), CancellationToken.None);
        var writing = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var finish = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _cache.BeforeSet = async key =>
        {
            if (key.EndsWith(":audience", StringComparison.Ordinal))
            {
                writing.SetResult();
                await finish.Task.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
            }
        };
        var write = _store.SetAccessToken(sessionId, "audience", new("access-token", _time.GetUtcNow().AddHours(1), _time.GetUtcNow().AddMinutes(59)), _time.GetUtcNow().AddMinutes(59), CancellationToken.None);
        await writing.Task.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
        var logout = _store.Remove(sessionId, CancellationToken.None);
        finish.SetResult();
        await Task.WhenAll(write, logout).WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
        _session = await _store.Get(sessionId, CancellationToken.None);
        _remainingToken = await _cache.GetAsync(_cache.Written.Keys.Single(_ => _.EndsWith(":audience", StringComparison.Ordinal)));
    }

    [Fact] void should_remove_the_session() => _session.ShouldBeNull();
    [Fact] void should_not_leave_a_token_written_after_removal() => _remainingToken.ShouldBeNull();
}
