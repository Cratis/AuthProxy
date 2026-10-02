// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.AccessTokens.given;

namespace Cratis.AuthProxy.AccessTokens.for_UserAccessTokens;

public class when_the_provider_rejects_the_refresh_token : given.user_access_tokens
{
    UserAccessTokenResult _result;
    UserAccessTokenResult _second;
    UserTokenSession? _session;

    async Task Because()
    {
        _endpoint.Answer = () => TokenEndpoint.Error("invalid_grant");
        _result = await Get();
        _second = await Get();
        _session = await _store.Get(_sessionId, CancellationToken.None);
    }

    [Fact] void should_fail() => _result.Failure.ShouldEqual(UserAccessTokenFailure.RefreshTokenRejected);
    [Fact] void should_reject_the_next_request_without_redeeming_again() => _second.Failure.ShouldEqual(UserAccessTokenFailure.RefreshTokenRejected);
    [Fact] void should_call_the_provider_only_once() => _endpoint.Received.Count.ShouldEqual(1);
    [Fact] void should_keep_the_session_for_other_audiences() => _session.ShouldNotBeNull();
}
