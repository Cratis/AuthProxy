// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens.for_UserTokenStore;

public class when_an_absolute_session_is_updated : given.a_user_token_store
{
    UserTokenSession? _before;
    UserTokenSession? _after;
    CachedUserAccessToken? _accessToken;

    async Task Because()
    {
        var sessionId = await _store.Create(new("workforce", "refresh-token"), CancellationToken.None);
        _time.Advance(TimeSpan.FromHours(11));
        await _store.Update(sessionId, new("workforce", "rotated-token"), CancellationToken.None);
        await _store.SetAccessToken(sessionId, "audience", new("access-token", _time.GetUtcNow().AddHours(2), _time.GetUtcNow().AddHours(1.5)), _time.GetUtcNow().AddHours(1.5), CancellationToken.None);
        _before = await _store.Get(sessionId, CancellationToken.None);
        _time.Advance(TimeSpan.FromHours(1));
        _after = await _store.Get(sessionId, CancellationToken.None);
        _accessToken = await _store.GetAccessToken(sessionId, "audience", CancellationToken.None);
    }

    [Fact] void should_keep_the_rotation_until_the_original_deadline() => _before!.RefreshToken.ShouldEqual("rotated-token");
    [Fact] void should_not_extend_the_absolute_session_deadline() => _after.ShouldBeNull();
    [Fact] void should_not_retain_an_access_token_past_the_session_deadline() => _accessToken.ShouldBeNull();
}
