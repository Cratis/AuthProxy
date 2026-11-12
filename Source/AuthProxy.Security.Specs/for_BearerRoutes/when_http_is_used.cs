// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

[Collection(BearerRouteSpecCollection.Name)]
public class when_http_is_used(BearerRouteHarness harness)
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task should_refuse_before_discovery_or_forwarding_even_with_a_forged_scheme(bool credential)
    {
        using var client = harness.CreateBearerClient();
        client.BaseAddress = new Uri("http://public.example.test");
        const string path = "/mcp/insecure";
        harness.Origin.Clear();
        var metadataRequests = harness.Issuer.MetadataRequests;
        using var request = credential
            ? BearerRouteHarness.WithToken(HttpMethod.Get, path, harness.Issuer.Token())
            : new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.TryAddWithoutValidation("X-Forwarded-Proto", "https");
        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("{\"error\":\"invalid_request\"}", await response.Content.ReadAsStringAsync());
        Assert.True(response.Headers.CacheControl?.NoStore);
        Assert.Empty(response.Headers.WwwAuthenticate);
        Assert.Null(response.Headers.Location);
        Assert.Equal(metadataRequests, harness.Issuer.MetadataRequests);
        Assert.False(harness.Origin.ReceivedAnythingFor(path));
    }
}
