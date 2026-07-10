// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Text.Json;
using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.Scenarios.when_client_credentials_token_is_requested;

[Collection(ClientCredentialsScenarioCollection.Name)]
public class and_an_access_token_is_used_as_a_refresh_token : Specification
{
    HttpResponseMessage _response;
    JsonDocument _payload;

    async Task Establish()
    {
        var factory = new AuthProxyFactory();
        using var client = factory.CreateTestClient();

        var initialResponse = await client.PostAsync(
            WellKnownPaths.Token,
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = ClientCredentialsDefaults.GrantType,
                ["service"] = "portal",
                ["client_id"] = "orders-api",
                ["client_secret"] = "super-secret",
            }));

        var initialPayload = JsonDocument.Parse(await initialResponse.Content.ReadAsStringAsync());
        var accessToken = initialPayload.RootElement.GetProperty("access_token").GetString()!;

        _response = await client.PostAsync(
            WellKnownPaths.Token,
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = ClientCredentialsDefaults.RefreshGrantType,
                ["refresh_token"] = accessToken,
            }));

        _payload = JsonDocument.Parse(await _response.Content.ReadAsStringAsync());
    }

    [Fact] void should_return_unauthorized() => _response.StatusCode.ShouldEqual(HttpStatusCode.Unauthorized);
    [Fact] void should_return_an_invalid_grant_error() => _payload.RootElement.GetProperty("error").GetString().ShouldEqual("invalid_grant");
}
