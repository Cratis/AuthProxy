// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

/// <summary>
/// A token that cannot be checked is not a token that is wrong. When the issuer's metadata and keys cannot be
/// retrieved the request is refused with <c language="text">503</c> and a <c language="text">Retry-After</c>, never forwarded, and
/// not answered with an <c language="text">invalid_token</c> challenge that would send the client to sign in again.
/// </summary>
/// <param name="harness">The running proxy, origin and issuer.</param>
[Collection(BearerRouteSpecCollection.Name)]
public class when_the_issuer_cannot_be_reached(BearerRouteHarness harness) : IAsyncLifetime
{
    const string Path = $"{BearerRouteHarness.UnreachableRoutePrefix}/items";

    HttpResponseMessage? _response;
    bool _forwarded;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateBearerClient();
        harness.Origin.Clear();

        _response = await client.SendAsync(BearerRouteHarness.WithToken(
            HttpMethod.Get,
            Path,
            harness.Issuer.Token(issuer: BearerRouteHarness.UnreachableIssuer)));
        _forwarded = harness.Origin.ReceivedAnythingFor(Path);
    }

    public Task DisposeAsync()
    {
        _response?.Dispose();
        return Task.CompletedTask;
    }

    [Fact] public void should_answer_service_unavailable() => Assert.Equal(HttpStatusCode.ServiceUnavailable, _response!.StatusCode);
    [Fact] public void should_ask_the_client_to_retry_later() => Assert.Equal(TimeSpan.FromSeconds(30), _response!.Headers.RetryAfter?.Delta);
    [Fact] public void should_not_challenge() => Assert.Empty(_response!.Headers.WwwAuthenticate);
    [Fact] public void should_not_be_cached() => Assert.True(_response!.Headers.CacheControl?.NoStore);
    [Fact] public void should_not_forward_anything() => Assert.False(_forwarded);
}
