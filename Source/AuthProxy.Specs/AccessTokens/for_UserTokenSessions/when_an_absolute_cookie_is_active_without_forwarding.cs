// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens.for_UserTokenSessions;

public class when_an_absolute_cookie_is_active_without_forwarding : given.a_cookie_token_session
{
    UserAccessTokenResult _result;

    async Task Establish()
    {
        _cookie.SlidingExpiration = false;
        _config.Session.SlidingExpiration = false;
        _sessionId = await _store.Create(new(Scheme, "refresh-token"), CancellationToken.None);
    }

    async Task Because()
    {
        _time.Advance(TimeSpan.FromSeconds(40));
        await ValidateCookie();
        _time.Advance(TimeSpan.FromSeconds(40));
        _result = await Get();
    }

    [Fact] void should_not_extend_the_absolute_token_session() => _result.Failure.ShouldEqual(UserAccessTokenFailure.NoRefreshToken);
    [Fact] void should_not_call_the_provider() => _endpoint.Received.ShouldBeEmpty();
}
