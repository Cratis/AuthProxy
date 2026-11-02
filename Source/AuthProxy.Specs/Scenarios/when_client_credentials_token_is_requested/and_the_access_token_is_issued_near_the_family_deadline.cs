// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Scenarios.when_client_credentials_token_is_requested;

[Collection(ClientCredentialsScenarioCollection.Name)]
public class and_the_access_token_is_issued_near_the_family_deadline : Specification
{
    TokenResponse _response;

    async Task Establish()
    {
        var factory = new ClockedAuthProxyFactory();
        using var client = factory.CreateTestClient();
        var initial = await TokenEndpoint.RequestAsync(client);
        factory.Time.Advance(TimeSpan.FromDays(30) - TimeSpan.FromMinutes(10));
        _response = await TokenEndpoint.RefreshAsync(client, initial.RefreshToken);
    }

    [Fact] void should_return_ok() => _response.Status.ShouldEqual(HttpStatusCode.OK);
    [Fact] void should_not_outlive_the_family_deadline() => (_response.Body.GetProperty("expires_in").GetInt32() <= 600).ShouldBeTrue();
}
