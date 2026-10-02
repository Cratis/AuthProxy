// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.AccessTokens.given;

namespace Cratis.AuthProxy.AccessTokens.for_UserAccessTokens;

public class when_two_audiences_are_requested : given.user_access_tokens
{
    UserAccessTokenResult _reporting;
    UserAccessTokenResult _billing;

    async Task Because()
    {
        _endpoint.Answer = () => TokenEndpoint.Bearer("reporting-token", 3600);
        _reporting = await Get();
        _accessToken = new() { Resource = "https://billing.example.com" };
        _endpoint.Answer = () => TokenEndpoint.Bearer("billing-token", 3600);
        _billing = await Get();
    }

    [Fact] void should_keep_a_token_per_audience() => (_reporting.Token, _billing.Token).ShouldEqual(("reporting-token", "billing-token"));
    [Fact] void should_send_the_resource_indicator() => _endpoint.Received[1]["resource"].ShouldEqual("https://billing.example.com");
}
