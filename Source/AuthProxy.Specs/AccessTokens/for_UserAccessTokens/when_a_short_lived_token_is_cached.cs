// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.AccessTokens.given;

namespace Cratis.AuthProxy.AccessTokens.for_UserAccessTokens;

public class when_a_short_lived_token_is_cached : given.user_access_tokens
{
    UserAccessTokenResult _reused;
    UserAccessTokenResult _renewed;
    int _callsBeforeRenewal;

    async Task Because()
    {
        _endpoint.Answer = () => TokenEndpoint.Bearer("short-token", 60);
        await Get();
        _time.Advance(TimeSpan.FromSeconds(29));
        _reused = await Get();
        _callsBeforeRenewal = _endpoint.Received.Count;
        _time.Advance(TimeSpan.FromSeconds(1));
        _endpoint.Answer = () => TokenEndpoint.Bearer("renewed-token", 60);
        _renewed = await Get();
    }

    [Fact] void should_reuse_the_token_before_its_half_life() => _reused.Token.ShouldEqual("short-token");
    [Fact] void should_not_refresh_on_each_request() => _callsBeforeRenewal.ShouldEqual(1);
    [Fact] void should_renew_at_the_half_life() => _renewed.Token.ShouldEqual("renewed-token");
    [Fact] void should_refresh_only_twice() => _endpoint.Received.Count.ShouldEqual(2);
}
