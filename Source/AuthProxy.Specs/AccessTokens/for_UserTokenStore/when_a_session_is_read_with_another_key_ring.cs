// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.DataProtection;

namespace Cratis.AuthProxy.AccessTokens.for_UserTokenStore;

public class when_a_session_is_read_with_another_key_ring : given.a_user_token_store
{
    string _sessionId;
    UserTokenSession? _read;

    async Task Because()
    {
        _sessionId = await _store.Create(new("workforce", "refresh-token"), CancellationToken.None);
        var config = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        config.CurrentValue.Returns(new C.AuthProxy());
        var other = new UserTokenStore(_cache, new EphemeralDataProtectionProvider(), config, _time);
        _read = await other.Get(_sessionId, CancellationToken.None);
    }

    [Fact] void should_treat_it_as_absent() => _read.ShouldBeNull();
}
