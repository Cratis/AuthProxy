// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Text.Json;
using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.Scenarios.when_client_credentials_token_is_requested;

[Collection(ClientCredentialsScenarioCollection.Name)]
public class and_a_valid_refresh_token_is_presented : Specification
{
    HttpResponseMessage _response;
    JsonDocument _payload;
    string _originalAccessToken;

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
        _originalAccessToken = initialPayload.RootElement.GetProperty("access_token").GetString()!;
        var refreshToken = initialPayload.RootElement.GetProperty("refresh_token").GetString()!;

        _response = await client.PostAsync(
            WellKnownPaths.Token,
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = ClientCredentialsDefaults.RefreshGrantType,
                ["refresh_token"] = refreshToken,
            }));

        _payload = JsonDocument.Parse(await _response.Content.ReadAsStringAsync());
    }

    [Fact] void should_return_ok() => _response.StatusCode.ShouldEqual(HttpStatusCode.OK);
    [Fact] void should_return_a_new_access_token()
    {
        var accessToken = _payload.RootElement.GetProperty("access_token").GetString();
        string.IsNullOrWhiteSpace(accessToken).ShouldBeFalse();
        (accessToken == _originalAccessToken).ShouldBeFalse();
    }
    [Fact] void should_return_the_token_lifetime() => _payload.RootElement.GetProperty("expires_in").GetInt32().ShouldEqual(3600);
    [Fact] void should_return_a_new_refresh_token() => string.IsNullOrWhiteSpace(_payload.RootElement.GetProperty("refresh_token").GetString()).ShouldBeFalse();
}
