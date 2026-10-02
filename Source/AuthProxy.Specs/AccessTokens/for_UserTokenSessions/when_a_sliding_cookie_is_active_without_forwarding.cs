// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens.for_UserTokenSessions;

public class when_a_sliding_cookie_is_active_without_forwarding : given.a_cookie_token_session
{
    UserAccessTokenResult _result;

    async Task Because()
    {
        for (var request = 0; request < 3; request++)
        {
            _time.Advance(TimeSpan.FromSeconds(40));
            await ValidateCookie();
        }

        _time.Advance(TimeSpan.FromSeconds(40));
        _result = await Get();
    }

    [Fact] void should_still_forward_the_users_token_after_the_original_lifetime() => _result.Token.ShouldEqual("access-token");
    [Fact] void should_redeem_only_for_the_forwarding_request() => _endpoint.Received.Count.ShouldEqual(1);
}
