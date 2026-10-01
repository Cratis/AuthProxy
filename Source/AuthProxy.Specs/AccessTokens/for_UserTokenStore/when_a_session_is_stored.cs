// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;

namespace Cratis.AuthProxy.AccessTokens.for_UserTokenStore;

public class when_a_session_is_stored : given.a_user_token_store
{
    const string RefreshToken = "refresh-token-value";

    string _sessionId;
    UserTokenSession? _read;
    bool _cacheHoldsTheRefreshTokenInClear;

    async Task Because()
    {
        _sessionId = await _store.Create(new("workforce", RefreshToken), CancellationToken.None);
        _read = await _store.Get(_sessionId, CancellationToken.None);

        _cacheHoldsTheRefreshTokenInClear = _cache.Written
            .Any(_ => _.Key.Contains(_sessionId, StringComparison.Ordinal)
                || Encoding.UTF8.GetString(_.Value).Contains(RefreshToken, StringComparison.Ordinal));
    }

    [Fact] void should_read_back_the_session() => _read.ShouldEqual(new UserTokenSession("workforce", RefreshToken));
    [Fact] void should_identify_it_unguessably() => _sessionId.Length.ShouldEqual(43);
    [Fact] void should_keep_neither_the_refresh_token_nor_the_session_identifier_in_clear() => _cacheHoldsTheRefreshTokenInClear.ShouldBeFalse();
}
