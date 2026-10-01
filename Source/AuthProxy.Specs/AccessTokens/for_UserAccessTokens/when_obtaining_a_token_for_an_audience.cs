// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens.for_UserAccessTokens;

public class when_obtaining_a_token_for_an_audience : given.user_access_tokens
{
    UserAccessTokenResult _first;
    UserAccessTokenResult _second;

    async Task Because()
    {
        _first = await Get();
        _second = await Get();
    }

    [Fact] void should_obtain_the_token() => _first.Token.ShouldEqual("access-token");
    [Fact] void should_redeem_the_refresh_token() => _endpoint.Received[0]["grant_type"].ShouldEqual("refresh_token");
    [Fact] void should_present_the_sessions_refresh_token() => _endpoint.Received[0]["refresh_token"].ShouldEqual("refresh-token");
    [Fact] void should_ask_for_the_audiences_scopes() => _endpoint.Received[0]["scope"].ShouldEqual("api://reporting/access_as_user");
    [Fact] void should_authenticate_with_the_client_secret() => _endpoint.Received[0]["client_secret"].ShouldEqual("client-secret");
    [Fact] void should_identify_the_client() => _endpoint.Received[0]["client_id"].ShouldEqual("client-id");
    [Fact] void should_answer_again_from_the_cache() => _second.Token.ShouldEqual("access-token");
    [Fact] void should_call_the_provider_once() => _endpoint.Received.Count.ShouldEqual(1);
}
