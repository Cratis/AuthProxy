// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.AccessTokens.given;

namespace Cratis.AuthProxy.AccessTokens.for_UserAccessTokens;

public class when_the_provider_answers_without_a_bearer_token : given.user_access_tokens
{
    UserAccessTokenResult _result;

    async Task Because()
    {
        _endpoint.Answer = () => TokenEndpoint.Json(System.Net.HttpStatusCode.OK, """{"access_token":"token","token_type":"DPoP","expires_in":3600}""");
        _result = await Get();
    }

    [Fact] void should_fail() => _result.Failure.ShouldEqual(UserAccessTokenFailure.ProviderUnavailable);
}
