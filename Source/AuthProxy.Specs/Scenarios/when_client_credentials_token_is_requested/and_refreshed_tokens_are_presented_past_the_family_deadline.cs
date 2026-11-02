// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Scenarios.when_client_credentials_token_is_requested;

[Collection(ClientCredentialsScenarioCollection.Name)]
public class and_refreshed_tokens_are_presented_past_the_family_deadline : Specification
{
    TokenResponse _first;
    TokenResponse _second;
    TokenResponse _third;

    async Task Establish()
    {
        var factory = new ClockedAuthProxyFactory();
        using var client = factory.CreateTestClient();
        var initial = await TokenEndpoint.RequestAsync(client);
        factory.Time.Advance(TimeSpan.FromDays(10));
        _first = await TokenEndpoint.RefreshAsync(client, initial.RefreshToken);
        factory.Time.Advance(TimeSpan.FromDays(10));
        _second = await TokenEndpoint.RefreshAsync(client, _first.RefreshToken);
        factory.Time.Advance(TimeSpan.FromDays(10));
        _third = await TokenEndpoint.RefreshAsync(client, _second.RefreshToken);
    }

    [Fact] void should_accept_the_first_refresh() => _first.Status.ShouldEqual(HttpStatusCode.OK);
    [Fact] void should_accept_the_second_refresh() => _second.Status.ShouldEqual(HttpStatusCode.OK);
    [Fact] void should_refuse_the_refresh_at_the_original_deadline() => _third.Status.ShouldEqual(HttpStatusCode.Unauthorized);
    [Fact] void should_report_an_invalid_grant() => _third.Error.ShouldEqual("invalid_grant");
}
