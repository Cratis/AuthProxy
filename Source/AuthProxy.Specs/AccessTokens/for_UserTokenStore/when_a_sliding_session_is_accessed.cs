// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens.for_UserTokenStore;

public class when_a_sliding_session_is_accessed : given.a_user_token_store
{
    UserTokenSession? _active;
    UserTokenSession? _expired;

    void Establish() => _config.Session.SlidingExpiration = true;

    async Task Because()
    {
        var sessionId = await _store.Create(new("workforce", "refresh-token"), CancellationToken.None);
        _time.Advance(TimeSpan.FromHours(11));
        await _store.Get(sessionId, CancellationToken.None);
        _time.Advance(TimeSpan.FromHours(11));
        _active = await _store.Get(sessionId, CancellationToken.None);
        _time.Advance(TimeSpan.FromHours(12));
        _expired = await _store.Get(sessionId, CancellationToken.None);
    }

    [Fact] void should_extend_the_deadline_when_accessed() => _active.ShouldNotBeNull();
    [Fact] void should_expire_after_an_idle_lifetime() => _expired.ShouldBeNull();
}
