// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.AccessTokens.given;

namespace Cratis.AuthProxy.AccessTokens.for_UserAccessTokens;

public class when_the_cached_token_is_about_to_expire : given.user_access_tokens
{
    UserAccessTokenResult _renewed;

    async Task Because()
    {
        await Get();
        _endpoint.Answer = () => TokenEndpoint.Bearer("renewed-token", 3600);
        _time.Advance(TimeSpan.FromMinutes(59.5));
        _renewed = await Get();
    }

    [Fact] void should_renew_it_before_it_expires() => _renewed.Token.ShouldEqual("renewed-token");
    [Fact] void should_call_the_provider_again() => _endpoint.Received.Count.ShouldEqual(2);
}
