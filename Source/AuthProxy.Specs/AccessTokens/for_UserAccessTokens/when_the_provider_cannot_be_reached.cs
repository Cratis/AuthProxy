// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.AccessTokens.for_UserAccessTokens;

public class when_the_provider_cannot_be_reached : given.user_access_tokens
{
    UserAccessTokenResult _result;
    UserTokenSession? _session;

    async Task Because()
    {
        _endpoint.Answer = () => throw new HttpRequestException("connection refused");
        _result = await Get();
        _session = await _store.Get(_sessionId, CancellationToken.None);
    }

    [Fact] void should_fail() => _result.Failure.ShouldEqual(UserAccessTokenFailure.ProviderUnavailable);
    [Fact] void should_keep_the_refresh_token_for_a_later_attempt() => _session.ShouldNotBeNull();
}
