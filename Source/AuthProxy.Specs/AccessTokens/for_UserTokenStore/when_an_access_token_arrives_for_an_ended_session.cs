// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens.for_UserTokenStore;

public class when_an_access_token_arrives_for_an_ended_session : given.a_user_token_store
{
    CachedUserAccessToken? _accessToken;

    async Task Because()
    {
        await _store.SetAccessToken("ended-session", "audience", new("access-token", _time.GetUtcNow().AddHours(1)), _time.GetUtcNow().AddMinutes(59), CancellationToken.None);
        _accessToken = await _store.GetAccessToken("ended-session", "audience", CancellationToken.None);
    }

    [Fact] void should_keep_nothing() => _accessToken.ShouldBeNull();
}
