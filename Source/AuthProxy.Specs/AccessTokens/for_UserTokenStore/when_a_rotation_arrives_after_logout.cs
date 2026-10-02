// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens.for_UserTokenStore;

public class when_a_rotation_arrives_after_logout : given.a_user_token_store
{
    UserTokenSession? _session;

    async Task Because()
    {
        var sessionId = await _store.Create(new("workforce", "refresh-token"), CancellationToken.None);
        await _store.Remove(sessionId, CancellationToken.None);
        await _store.Update(sessionId, new("workforce", "rotated-token"), CancellationToken.None);
        _session = await _store.Get(sessionId, CancellationToken.None);
    }

    [Fact] void should_not_recreate_the_session() => _session.ShouldBeNull();
}
