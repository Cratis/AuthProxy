// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Configuration;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteConfigurationValidator;

public class when_token_exchange_is_misconfigured
{
    [Theory]
    [InlineData("TokenExchange:Endpoint", "http://identity.example/connect/token")]
    [InlineData("TokenExchange:Endpoint", "https://identity.example/connect/token?q=x")]
    [InlineData("TokenExchange:Endpoint", "https://identity.example/connect/token#fragment")]
    [InlineData("TokenExchange:Endpoint", "https://user@identity.example/connect/token")]
    [InlineData("TokenExchange:ClientId", " ")]
    [InlineData("TokenExchange:ClientSecret", "")]
    [InlineData("TokenExchange:Scopes:0", "")]
    [InlineData("TokenExchange:Scopes:0", "offline_access")]
    [InlineData("TokenExchange:Audience", "")]
    [InlineData("TokenExchange:Audience", "other")]
    [InlineData("TokenExchange:Resource", "")]
    [InlineData("TokenExchange:Resource", "relative")]
    [InlineData("TokenExchange:Resource", "https://cratis.direct/mcp?q=tenant")]
    [InlineData("TokenExchange:Resource", "https://cratis.direct/mcp#fragment")]
    [InlineData("TokenExchange:Resource", "http://cratis.direct/mcp")]
    [InlineData("TokenExchange:ResultIssuer", "https://other.example")]
    [InlineData("TokenExchange:Issuers:0:Issuer", "https://identity.example")]
    [InlineData("TokenExchange:Issuers:0:Issuer", "relative")]
    [InlineData("TokenExchange:Issuers:0:Issuer", " ")]
    [InlineData("TokenExchange:Issuers:0:SubjectTokenType", "id_token")]
    [InlineData("TokenExchange:Issuers:1:Issuer", "https://external.example")]
    [InlineData("TokenExchange:Timeout", "00:00:00.099")]
    [InlineData("TokenExchange:Timeout", "00:00:11")]
    [InlineData("TokenExchange:MaximumCachedTokens", "0")]
    [InlineData("Issuers:1:Issuer", "https://external.example")]
    [InlineData("Dpop:PublicOrigin", "https://cratis.direct")]
    [InlineData("Issuers:0:Issuer", "")]
    public void should_refuse_an_unsafe_exchange_configuration(string key, string value) =>
        new BearerRouteConfigurationValidator().Validate(null, Configuration(key, value)).Failed.ShouldBeTrue();

    [Fact]
    public void should_require_an_external_issuer()
    {
        var configuration = Configuration();
        configuration.Services["app"].BearerRoutes[0].TokenExchange!.Issuers.Clear();
        new BearerRouteConfigurationValidator().Validate(null, configuration).Failed.ShouldBeTrue();
    }

    [Fact]
    public void should_require_scopes()
    {
        var configuration = Configuration();
        configuration.Services["app"].BearerRoutes[0].TokenExchange!.Scopes.Clear();
        new BearerRouteConfigurationValidator().Validate(null, configuration).Failed.ShouldBeTrue();
    }

    [Fact]
    public void should_accept_separate_resource_and_audience() =>
        new BearerRouteConfigurationValidator().Validate(null, Configuration()).Succeeded.ShouldBeTrue();

    [Fact]
    public void should_accept_a_urn_resource() =>
        new BearerRouteConfigurationValidator().Validate(null, Configuration("TokenExchange:Resource", "urn:cratis:direct")).Succeeded.ShouldBeTrue();

    internal static C.AuthProxy Configuration(string? key = null, string? value = null)
    {
        const string route = "Services:app:BearerRoutes:0:";
        var settings = new Dictionary<string, string?>
        {
            ["Services:app:Backend:BaseUrl"] = "https://backend.example",
            ["Services:app:IdentityVerification"] = "BestEffort",
            [route + "PathPrefix"] = "/mcp",
            [route + "Issuers:0:Issuer"] = "https://identity.example",
            [route + "Audiences:0"] = "direct-mcp",
            [route + "TokenExchange:Endpoint"] = "https://identity.example/connect/token",
            [route + "TokenExchange:ClientId"] = "synthetic-client",
            [route + "TokenExchange:ClientSecret"] = string.Concat("synthetic-", "not-a-credential"),
            [route + "TokenExchange:Resource"] = "https://cratis.direct/mcp",
            [route + "TokenExchange:Audience"] = "direct-mcp",
            [route + "TokenExchange:Scopes:0"] = "direct-mcp:read",
            [route + "TokenExchange:ResultIssuer"] = "https://identity.example",
            [route + "TokenExchange:Issuers:0:Issuer"] = "https://external.example",
        };
        if (key is not null) settings[route + key] = value;
        return new ConfigurationBuilder().AddInMemoryCollection(settings).Build().Get<C.AuthProxy>()!;
    }
}
