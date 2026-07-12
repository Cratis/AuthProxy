// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Text.Json;
using Cratis.AuthProxy.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Scenarios.when_client_credentials_token_is_requested;

[Collection(ClientCredentialsScenarioCollection.Name)]
public class and_verification_response_includes_a_tenant : Specification
{
    HttpResponseMessage _response;
    JsonDocument _payload;
    TenantAuthProxyFactory _factory;

    async Task Establish()
    {
        _factory = new TenantAuthProxyFactory();
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
    [Fact] void should_embed_the_tenant_in_the_access_token()
    {
        var tokenProtector = _factory.Services.GetRequiredService<ClientCredentialsTokenProtector>();
        var accessToken = _payload.RootElement.GetProperty("access_token").GetString()!;
        tokenProtector.TryValidate(accessToken, out var tokenPayload).ShouldBeTrue();
        tokenPayload.Tenant.ShouldEqual(TenantAuthProxyFactory.VerifiedTenant);
    }
    [Fact] void should_embed_the_tenant_in_the_refresh_token()
    {
        var tokenProtector = _factory.Services.GetRequiredService<ClientCredentialsTokenProtector>();
        var refreshToken = _payload.RootElement.GetProperty("refresh_token").GetString()!;
        tokenProtector.TryValidateRefreshToken(refreshToken, out var tokenPayload).ShouldBeTrue();
        tokenPayload.Tenant.ShouldEqual(TenantAuthProxyFactory.VerifiedTenant);
    }
}
