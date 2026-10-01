// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens.for_UserAccessTokens;

public class when_the_service_requires_another_provider : given.user_access_tokens
{
    UserAccessTokenResult _result;

    async Task Because()
    {
        _accessToken.Provider = "Partners";
        _result = await Get();
    }

    [Fact] void should_fail() => _result.Failure.ShouldEqual(UserAccessTokenFailure.WrongProvider);
    [Fact] void should_not_call_the_provider() => _endpoint.Received.ShouldBeEmpty();
}
