// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens.for_UserTokenStore;

public class when_a_session_is_removed : given.a_user_token_store
{
    string _sessionId;
    UserTokenSession? _session;
    CachedUserAccessToken? _accessToken;

    async Task Establish()
    {
        _sessionId = await _store.Create(new("workforce", "refresh-token"), CancellationToken.None);
        await _store.SetAccessToken(_sessionId, "audience", new("access-token", _time.GetUtcNow().AddHours(1)), _time.GetUtcNow().AddMinutes(59), CancellationToken.None);
    }

    async Task Because()
    {
        await _store.Remove(_sessionId, CancellationToken.None);
        _session = await _store.Get(_sessionId, CancellationToken.None);
        _accessToken = await _store.GetAccessToken(_sessionId, "audience", CancellationToken.None);
    }

    [Fact] void should_forget_the_refresh_token() => _session.ShouldBeNull();
    [Fact] void should_forget_the_access_tokens_obtained_for_it() => _accessToken.ShouldBeNull();
}
