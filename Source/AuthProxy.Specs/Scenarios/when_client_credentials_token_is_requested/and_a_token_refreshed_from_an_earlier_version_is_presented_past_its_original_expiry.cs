// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Scenarios.when_client_credentials_token_is_requested;

[Collection(ClientCredentialsScenarioCollection.Name)]
public class and_a_token_refreshed_from_an_earlier_version_is_presented_past_its_original_expiry : Specification
{
    TokenResponse _refreshed;
    TokenResponse _afterOriginalExpiry;

    async Task Establish()
    {
        var factory = new ClockedAuthProxyFactory();
        using var client = factory.CreateTestClient();
        var legacy = EarlierVersionRefreshToken.Create(factory, TimeSpan.FromDays(2));
        factory.Time.Advance(TimeSpan.FromDays(1));
        _refreshed = await TokenEndpoint.RefreshAsync(client, legacy);
        factory.Time.Advance(TimeSpan.FromDays(1));
        _afterOriginalExpiry = await TokenEndpoint.RefreshAsync(client, _refreshed.RefreshToken);
    }

    [Fact] void should_accept_the_refresh_before_the_original_expiry() => _refreshed.Status.ShouldEqual(HttpStatusCode.OK);
    [Fact] void should_refuse_the_refreshed_token_at_the_original_expiry() => _afterOriginalExpiry.Status.ShouldEqual(HttpStatusCode.Unauthorized);
}
