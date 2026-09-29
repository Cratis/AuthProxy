// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

/// <summary>
/// The tenant comes from the token and from nowhere else. A token without <c language="text">tid</c> is refused rather than
/// resolved through the browser tenant selection, and never falls back to a default tenant.
/// </summary>
/// <param name="harness">The running proxy, origin and issuer.</param>
[Collection(BearerRouteSpecCollection.Name)]
public class when_the_token_has_no_tenant(BearerRouteHarness harness) : IAsyncLifetime
{
    const string Path = $"{BearerRouteHarness.RoutePrefix}/tools";

    HttpResponseMessage? _response;
    bool _forwarded;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateBearerClient();
        harness.Origin.Clear();

        _response = await client.SendAsync(BearerRouteHarness.WithToken(HttpMethod.Get, Path, harness.Issuer.Token(without: "tid")));
        _forwarded = harness.Origin.ReceivedAnythingFor(Path);
    }

    public Task DisposeAsync()
    {
        _response?.Dispose();
        return Task.CompletedTask;
    }

    [Fact] public void should_refuse_it() => Assert.Equal(HttpStatusCode.Forbidden, _response!.StatusCode);
    [Fact] public void should_not_forward_anything() => Assert.False(_forwarded);
}
