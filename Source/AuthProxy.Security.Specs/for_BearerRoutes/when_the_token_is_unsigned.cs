// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

/// <summary>
/// An <c language="text">alg: none</c> token carries every claim a valid one does and proves none of them.
/// </summary>
/// <param name="harness">The running proxy, origin and issuer.</param>
[Collection(BearerRouteSpecCollection.Name)]
public class when_the_token_is_unsigned(BearerRouteHarness harness) : IAsyncLifetime
{
    const string Path = $"{BearerRouteHarness.RoutePrefix}/tools";

    HttpResponseMessage? _response;
    bool _forwarded;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateBearerClient();
        harness.Origin.Clear();

        _response = await client.SendAsync(BearerRouteHarness.WithToken(HttpMethod.Get, Path, harness.Issuer.UnsignedToken()));
        _forwarded = harness.Origin.ReceivedAnythingFor(Path);
    }

    public Task DisposeAsync()
    {
        _response?.Dispose();
        return Task.CompletedTask;
    }

    [Fact] public void should_refuse_it() => Assert.Equal(HttpStatusCode.Unauthorized, _response!.StatusCode);
    [Fact] public void should_not_forward_anything() => Assert.False(_forwarded);
    [Fact] public void should_challenge_with_invalid_token() =>
        Assert.Equal($"Bearer error=\"invalid_token\", resource_metadata=\"{BearerRouteHarness.ResourceMetadataUrl}\"", _response!.Headers.WwwAuthenticate.ToString());
}
