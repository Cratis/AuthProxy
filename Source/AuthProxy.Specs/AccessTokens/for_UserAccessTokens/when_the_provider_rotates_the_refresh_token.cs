// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.AccessTokens.given;

namespace Cratis.AuthProxy.AccessTokens.for_UserAccessTokens;

public class when_the_provider_rotates_the_refresh_token : given.user_access_tokens
{
    async Task Because()
    {
        _endpoint.Answer = () => TokenEndpoint.Bearer("access-token", 3600, refreshToken: "rotated-refresh-token");
        await Get();
        _accessToken = new() { Scopes = ["api://billing/access_as_user"] };
        await Get();
    }

    [Fact] void should_present_the_rotated_refresh_token_next() => _endpoint.Received[1]["refresh_token"].ShouldEqual("rotated-refresh-token");
}
