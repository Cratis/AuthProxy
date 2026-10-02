// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

public class when_repeated_separators_hide_the_only_bearer_route
{
    [Theory]
    [InlineData("/api//mcp/tools")]
    [InlineData("/api///mcp/tools")]
    public async Task should_not_forward_a_browser_session_to_a_normalizing_backend(string path)
    {
        await using var harness = new SingleRouteHarness();
        using var client = harness.CreateBearerClient();

        // This origin serves the bearer resource when it collapses the repeated separators.
        using var origin = new HttpClient();
        using var direct = await origin.GetAsync($"{harness.Origin.BaseUrl.TrimEnd('/')}{path}");
        Assert.Equal(HttpStatusCode.OK, direct.StatusCode);
        Assert.True(harness.Origin.ReceivedAnythingFor("/api/mcp/tools"));
        harness.Origin.Clear();

        using var browserRequest = SecurityHarness.Authenticated(HttpMethod.Get, "/api/items", "browser-user");
        using var browser = await client.SendAsync(browserRequest);
        Assert.Equal(HttpStatusCode.OK, browser.StatusCode);
        Assert.NotNull(harness.Origin.LastRequestTo("/api/items"));

        using var canonicalRequest = SecurityHarness.Authenticated(HttpMethod.Get, "/api/mcp/tools", "browser-user");
        using var canonical = await client.SendAsync(canonicalRequest);
        Assert.Equal(HttpStatusCode.Unauthorized, canonical.StatusCode);
        harness.Origin.Clear();

        using var request = SecurityHarness.Authenticated(HttpMethod.Get, path, "browser-user");
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Empty(harness.Origin.Received);
    }

    sealed class SingleRouteHarness() : BearerRouteHarness(normalizeRepeatedSeparators: true)
    {
        protected override void AddSettings(IDictionary<string, string?> settings)
        {
            const string routes = $"{C.AuthProxy.SectionKey}:Services:app:BearerRoutes";
            foreach (var key in settings.Keys.Where(_ => _.StartsWith($"{routes}:1:", StringComparison.Ordinal)
                || _.StartsWith($"{routes}:2:", StringComparison.Ordinal)).ToArray())
            {
                settings.Remove(key);
            }

            settings[$"{routes}:0:PathPrefix"] = "/api/mcp";
            settings[$"{routes}:0:RequiredClaims:0:Claim"] = "membership";
            settings[$"{routes}:0:RequiredClaims:0:AnyOf:0"] = "allowed";
        }
    }
}
