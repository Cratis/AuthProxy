// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.AccessTokens.given;

namespace Cratis.AuthProxy.AccessTokens.for_UserAccessTokens;

public class when_a_refresh_rejection_backoff_expires : given.user_access_tokens
{
    UserAccessTokenResult _result;

    async Task Establish()
    {
        _endpoint.Answer = () => TokenEndpoint.Error("invalid_grant");
        await Get();
        _time.Advance(TimeSpan.FromSeconds(30));
        _endpoint.Answer = () => TokenEndpoint.Bearer("renewed-token", 3600);
    }

    async Task Because() => _result = await Get();

    [Fact] void should_retry_the_provider() => _endpoint.Received.Count.ShouldEqual(2);
    [Fact] void should_forward_the_new_token() => _result.Token.ShouldEqual("renewed-token");
}
