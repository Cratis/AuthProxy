// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;

namespace Cratis.AuthProxy.Security.for_AccessControl;

/// <summary>
/// The service forwarded to an origin must identify the route that won, not a caller's losing selector.
/// </summary>
/// <param name="harness">The proxy with the first recording origin.</param>
[Collection(SecuritySpecCollection.Name)]
public class when_service_selectors_disagree_with_the_route(SecurityHarness harness)
{
    [Theory]
    [InlineData("/public", "admin", null, "app")]
    [InlineData("/public?service=admin", null, null, "app")]
    [InlineData("/api/test?service=admin", "unknown", null, "admin")]
    [InlineData("/api/test?service=admin", null, "unknown", "admin")]
    [InlineData("/api/test", null, "admin", "admin")]
    [InlineData("/api/test?service=admin", null, null, "admin")]
    public async Task should_forward_both_headers_with_the_actual_destination(string pathAndQuery, string? current, string? legacy, string expectedService)
    {
        await using var second = await RecordingBackend.Start();
        await using var proxy = harness.WithWebHostBuilder(builder => builder.ConfigureAppConfiguration((_, config) =>
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                [$"{C.AuthProxy.SectionKey}:Services:admin:Backend:BaseUrl"] = second.BaseUrl,
                [$"{C.AuthProxy.SectionKey}:Services:admin:ResolveIdentityDetails"] = "false",
                [$"{C.AuthProxy.SectionKey}:Services:app:ResolveIdentityDetails"] = "false",
            })));
        using var client = proxy.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });
        using var request = SecurityHarness.Authenticated(HttpMethod.Get, pathAndQuery);
        if (current is not null)
        {
            request.Headers.Add(Headers.ServiceId, current);
        }

        if (legacy is not null)
        {
            request.Headers.Add(Headers.LegacyServiceId, legacy);
        }

        harness.Origin.Clear();
        using var response = await client.SendAsync(request);
        var path = pathAndQuery.Split('?')[0];
        var selectedOrigin = expectedService == "app" ? harness.Origin : second;
        var otherOrigin = expectedService == "app" ? second : harness.Origin;
        var forwarded = selectedOrigin.LastRequestTo(path);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(forwarded);
        Assert.Equal(expectedService, forwarded.Value(Headers.ServiceId));
        Assert.Equal(expectedService, forwarded.Value(Headers.LegacyServiceId));
        Assert.False(otherOrigin.ReceivedAnythingFor(path));
    }

    [Fact]
    public async Task should_forward_the_only_service_on_a_catchall_despite_an_unknown_selector()
    {
        using var client = harness.CreateSecurityClient();
        using var request = SecurityHarness.Authenticated(HttpMethod.Get, "/private?service=unknown");
        request.Headers.Add(Headers.ServiceId, "unknown");
        harness.Origin.Clear();

        using var response = await client.SendAsync(request);
        var forwarded = harness.Origin.LastRequestTo("/private");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(forwarded);
        Assert.Equal("app", forwarded.Value(Headers.ServiceId));
        Assert.Equal("app", forwarded.Value(Headers.LegacyServiceId));
    }

    [Theory]
    [InlineData(Headers.ServiceId)]
    [InlineData(Headers.LegacyServiceId)]
    public async Task should_enforce_query_service_claims_when_the_header_names_an_unknown_service(string header)
    {
        await using var second = await RecordingBackend.Start();
        await using var proxy = harness.WithWebHostBuilder(builder => builder.ConfigureAppConfiguration((_, config) =>
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                [$"{C.AuthProxy.SectionKey}:Services:admin:Backend:BaseUrl"] = second.BaseUrl,
                [$"{C.AuthProxy.SectionKey}:Services:admin:Authorization:RequiredClaims:0:Claim"] = "role",
                [$"{C.AuthProxy.SectionKey}:Services:admin:Authorization:RequiredClaims:0:AnyOf:0"] = "admin",
            })));
        using var client = proxy.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });
        using var request = SecurityHarness.Authenticated(HttpMethod.Get, "/api/test?service=admin");
        request.Headers.Add(header, "unknown");
        harness.Origin.Clear();

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Empty(second.Received);
        Assert.Empty(harness.Origin.Received);
    }
}
