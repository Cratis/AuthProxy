// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Identity;

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

/// <summary>
/// Audience identifiers are exact: adding or removing a trailing slash names a different resource.
/// </summary>
public class when_a_token_audience_differs_by_a_trailing_slash
{
    [Theory]
    [InlineData("direct-api", "direct-api/", false, HttpStatusCode.Unauthorized)]
    [InlineData("direct-api/", "direct-api", false, HttpStatusCode.Unauthorized)]
    [InlineData("direct-api", "direct-api", false, HttpStatusCode.OK)]
    [InlineData("direct-api/", "direct-api/", false, HttpStatusCode.OK)]
    [InlineData("direct-api", "direct-api/", true, HttpStatusCode.OK)]
    [InlineData("direct-api/", "direct-api", true, HttpStatusCode.OK)]
    public async Task should_accept_only_an_explicitly_configured_audience(string configuredAudience, string tokenAudience, bool includeTokenAudience, HttpStatusCode expected)
    {
        const string path = "/mcp/exact-audience";
        await using var harness = new ExactAudienceHarness(configuredAudience, includeTokenAudience ? tokenAudience : null);
        using var client = harness.CreateBearerClient();
        using var request = BearerRouteHarness.WithToken(HttpMethod.Get, path, harness.Issuer.Token(new StubIssuer.TokenRequest { Audience = tokenAudience }));
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(expected, response.StatusCode);
        Assert.Equal(expected == HttpStatusCode.OK, harness.Origin.ReceivedAnythingFor(path));
        if (expected == HttpStatusCode.OK)
        {
            AssertResource(harness, path, tokenAudience);
        }
    }

    [Theory]
    [InlineData("resource-z", "resource-a")]
    [InlineData("resource-a", "resource-z")]
    public async Task should_choose_one_exact_resource_from_an_array_audience(string first, string second)
    {
        await using var harness = new ExactAudienceHarness(first, second);
        using var client = harness.CreateBearerClient();
        const string path = "/mcp/array-audience";
        var token = harness.Issuer.TokenShaped(descriptor =>
        {
            descriptor.Audience = null;
            descriptor.Claims["aud"] = new[] { "resource-z", "resource-a" };
        });
        using var request = BearerRouteHarness.WithToken(HttpMethod.Get, path, token);

        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        AssertResource(harness, path, "resource-a");
    }

    static void AssertResource(BearerRouteHarness harness, string path, string expected)
    {
        Assert.True(ClientPrincipal.TryFromBase64(harness.Origin.LastRequestTo(path)!.Value(Headers.Principal), out var principal));
        Assert.Equal(expected, Assert.Single(principal!.Claims, claim => claim.Type == "urn:cratis:bearer:resource").Value);
    }

    sealed class ExactAudienceHarness(string audience, string? additionalAudience) : BearerRouteHarness
    {
        protected override void AddSettings(IDictionary<string, string?> settings)
        {
            settings[$"{C.AuthProxy.SectionKey}:Services:app:BearerRoutes:0:Audiences:0"] = audience;
            if (additionalAudience is not null)
            {
                settings[$"{C.AuthProxy.SectionKey}:Services:app:BearerRoutes:0:Audiences:1"] = additionalAudience;
            }
        }
    }
}
