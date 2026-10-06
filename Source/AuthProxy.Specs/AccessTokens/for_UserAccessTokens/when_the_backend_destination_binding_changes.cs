// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.AccessTokens.given;

namespace Cratis.AuthProxy.AccessTokens.for_UserAccessTokens;

public class when_the_backend_destination_binding_changes : given.user_access_tokens
{
    UserAccessTokenResult _before;
    UserAccessTokenResult _after;

    async Task Because()
    {
        _accessToken.DestinationBinding = "backend-before";
        _endpoint.Answer = () => TokenEndpoint.Bearer("old-destination-token", 3600);
        _before = await Get();
        _accessToken.DestinationBinding = "backend-after";
        _endpoint.Answer = () => TokenEndpoint.Bearer("new-destination-token", 3600);
        _after = await Get();
    }

    [Fact] void should_obtain_the_original_token() => _before.Token.ShouldEqual("old-destination-token");
    [Fact] void should_obtain_a_new_token_for_the_new_destination() => _after.Token.ShouldEqual("new-destination-token");
    [Fact] void should_redeem_the_refresh_token_again_for_the_unchanged_audience() => _endpoint.Received.Count.ShouldEqual(2);
}
