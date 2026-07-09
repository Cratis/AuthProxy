// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Text.Json;
using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.Scenarios.when_client_credentials_token_is_requested;

[Collection(ClientCredentialsScenarioCollection.Name)]
public class and_valid_credentials_are_presented : Specification
{
    HttpResponseMessage _response;
    JsonDocument _payload;
    AuthProxyFactory _factory;

    async Task Establish()
    {
        _factory = new AuthProxyFactory();
        using var client = _factory.CreateTestClient();

        _response = await client.PostAsync(
            WellKnownPaths.Token,
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = ClientCredentialsDefaults.GrantType,
                ["service"] = "portal",
                ["client_id"] = "orders-api",
                ["client_secret"] = "super-secret",
            }));

        _payload = JsonDocument.Parse(await _response.Content.ReadAsStringAsync());
    }

    [Fact] void should_return_ok() => _response.StatusCode.ShouldEqual(HttpStatusCode.OK);
    [Fact] void should_return_a_bearer_token() => _payload.RootElement.GetProperty("token_type").GetString().ShouldEqual("Bearer");
    [Fact] void should_return_an_access_token() => string.IsNullOrWhiteSpace(_payload.RootElement.GetProperty("access_token").GetString()).ShouldBeFalse();
    [Fact] void should_return_the_token_lifetime() => _payload.RootElement.GetProperty("expires_in").GetInt32().ShouldEqual(3600);
    [Fact] void should_forward_the_well_known_verification_payload()
    {
        _factory.CapturedVerificationRequest.ShouldNotBeNull();
        _factory.CapturedVerificationRequest!.Service.ShouldEqual("portal");
        _factory.CapturedVerificationRequest.RoutePrefix.ShouldEqual("/api");
        _factory.CapturedVerificationRequest.ClientId.ShouldEqual("orders-api");
        _factory.CapturedVerificationRequest.ClientSecret.ShouldEqual("super-secret");
    }
}
