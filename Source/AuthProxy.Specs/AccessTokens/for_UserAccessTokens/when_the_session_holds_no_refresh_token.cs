// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens.for_UserAccessTokens;

public class when_the_session_holds_no_refresh_token : given.user_access_tokens
{
    UserAccessTokenResult _result;

    async Task Because() => _result = await _tokens.GetFor("unknown-session", _accessToken, CancellationToken.None);

    [Fact] void should_fail() => _result.Failure.ShouldEqual(UserAccessTokenFailure.NoRefreshToken);
    [Fact] void should_not_call_the_provider() => _endpoint.Received.ShouldBeEmpty();
}
