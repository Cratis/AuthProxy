// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.AccessTokens.given;

namespace Cratis.AuthProxy.AccessTokens.for_UserAccessTokens;

public class when_one_audience_requires_consent : given.user_access_tokens
{
    UserAccessTokenResult _refused;
    UserAccessTokenResult _other;

    async Task Because()
    {
        _endpoint.Answer = () => TokenEndpoint.Error("invalid_grant");
        _refused = await Get();
        _endpoint.Answer = () => TokenEndpoint.Bearer("other-audience-token", 3600);
        _other = await _tokens.GetFor(_sessionId, new() { Scopes = ["api://other/access_as_user"] }, CancellationToken.None);
    }

    [Fact] void should_refuse_only_the_affected_audience() => _refused.Succeeded.ShouldBeFalse();
    [Fact] void should_obtain_a_token_for_the_other_audience() => _other.Token.ShouldEqual("other-audience-token");
    [Fact] void should_redeem_the_original_refresh_token_for_the_other_audience() => _endpoint.Received[1]["refresh_token"].ShouldEqual("refresh-token");
}
