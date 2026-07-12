// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Text.Json;
using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.Scenarios.when_client_credentials_token_is_requested;

[Collection(ClientCredentialsScenarioCollection.Name)]
public class and_refresh_token_is_invalid : Specification
{
    HttpResponseMessage _response;
    JsonDocument _payload;

    async Task Establish()
    {
        await using var factory = new AuthProxyFactory();
        using var client = factory.CreateTestClient();

        _response = await client.PostAsync(
            WellKnownPaths.Token,
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = ClientCredentialsDefaults.RefreshGrantType,
                ["refresh_token"] = "not-a-real-refresh-token",
            }));

        _payload = JsonDocument.Parse(await _response.Content.ReadAsStringAsync());
    }

    [Fact] void should_return_unauthorized() => _response.StatusCode.ShouldEqual(HttpStatusCode.Unauthorized);
    [Fact] void should_return_an_invalid_grant_error() => _payload.RootElement.GetProperty("error").GetString().ShouldEqual("invalid_grant");
}
