// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

/// <summary>
/// A valid token without a scope the route requires is refused with <c language="text">insufficient_scope</c>, naming the
/// scope to ask for, so a client can request a token that has it.
/// </summary>
/// <param name="harness">The running proxy, origin and issuer.</param>
[Collection(BearerRouteSpecCollection.Name)]
public class when_the_token_lacks_a_required_scope(BearerRouteHarness harness) : IAsyncLifetime
{
    const string Path = $"{BearerRouteHarness.RoutePrefix}/tools";

    HttpResponseMessage? _response;
    bool _forwarded;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateBearerClient();
        harness.Origin.Clear();

        _response = await client.SendAsync(BearerRouteHarness.WithToken(HttpMethod.Get, Path, harness.Issuer.Token(new Dictionary<string, object> { ["scope"] = "direct:work" })));
        _forwarded = harness.Origin.ReceivedAnythingFor(Path);
    }

    public Task DisposeAsync()
    {
        _response?.Dispose();
        return Task.CompletedTask;
    }

    [Fact] public void should_refuse_it() => Assert.Equal(HttpStatusCode.Forbidden, _response!.StatusCode);
    [Fact] public void should_not_forward_anything() => Assert.False(_forwarded);
    [Fact] public void should_challenge_with_insufficient_scope() =>
        Assert.Equal(
            $"Bearer error=\"insufficient_scope\", scope=\"{BearerRouteHarness.RequiredScope}\", resource_metadata=\"{BearerRouteHarness.ResourceMetadataUrl}\"",
            _response!.Headers.WwwAuthenticate.ToString());
}
