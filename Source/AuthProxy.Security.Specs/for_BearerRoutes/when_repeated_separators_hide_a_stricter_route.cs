// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

public class when_repeated_separators_hide_a_stricter_route
{
    [Theory]
    [InlineData("/v1//admin")]
    [InlineData("/v1///admin/tools")]
    public async Task should_not_forward_a_broadly_authorized_token_to_a_normalizing_backend(string path)
    {
        await using var harness = new NestedRoutesHarness();
        using var client = harness.CreateBearerClient();
        var token = harness.Issuer.Token();

        // Demonstrate that this backend resolves the ambiguous path to the stricter route.
        using var origin = new HttpClient();
        using var direct = await origin.GetAsync($"{harness.Origin.BaseUrl.TrimEnd('/')}{path}");
        Assert.Equal(HttpStatusCode.OK, direct.StatusCode);
        Assert.True(harness.Origin.ReceivedAnythingFor(path.Replace("///", "/", StringComparison.Ordinal).Replace("//", "/", StringComparison.Ordinal)));
        harness.Origin.Clear();

        using var broad = await client.SendAsync(BearerRouteHarness.WithToken(HttpMethod.Get, "/v1/items", token));
        Assert.Equal(HttpStatusCode.OK, broad.StatusCode);
        using var narrow = await client.SendAsync(BearerRouteHarness.WithToken(HttpMethod.Get, "/v1/admin", token));
        Assert.Equal(HttpStatusCode.Forbidden, narrow.StatusCode);
        harness.Origin.Clear();

        using var ambiguous = await client.SendAsync(BearerRouteHarness.WithToken(HttpMethod.Get, path, token));
        Assert.Equal(HttpStatusCode.BadRequest, ambiguous.StatusCode);
        Assert.Equal("no-store", ambiguous.Headers.CacheControl?.ToString());
        Assert.Empty(harness.Origin.Received);
    }

    sealed class NestedRoutesHarness() : BearerRouteHarness(normalizeRepeatedSeparators: true)
    {
        protected override void AddSettings(IDictionary<string, string?> settings)
        {
            const string route = $"{C.AuthProxy.SectionKey}:Services:app:BearerRoutes:3";
            settings[$"{route}:PathPrefix"] = "/v1/admin";
            settings[$"{route}:Issuers:0:Issuer"] = Issuer.Issuer;
            settings[$"{route}:Audiences:0"] = Audience;
            settings[$"{route}:RequiredScopes:0"] = "admin:write";
        }
    }
}
