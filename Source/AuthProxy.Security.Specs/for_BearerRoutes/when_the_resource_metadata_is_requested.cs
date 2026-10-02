// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

/// <summary>
/// The protected-resource metadata document is how a client learns which authorization server to get a token
/// from, so it is served before the client has one: it passes through to the backend without authentication,
/// and without any identity, spoofed or otherwise.
/// </summary>
/// <param name="harness">The running proxy, origin and issuer.</param>
[Collection(BearerRouteSpecCollection.Name)]
public class when_the_resource_metadata_is_requested(BearerRouteHarness harness) : IAsyncLifetime
{
    HttpResponseMessage? _response;
    HttpResponseMessage? _post;
    ForwardedRequest? _forwarded;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateBearerClient();
        harness.Origin.Clear();

        var request = new HttpRequestMessage(HttpMethod.Get, BearerRouteHarness.ResourceMetadataPath);
        request.Headers.TryAddWithoutValidation(Headers.PrincipalId, "attacker");
        request.Headers.TryAddWithoutValidation(Headers.TenantId, "victim-tenant");
        _response = await client.SendAsync(request);
        _forwarded = harness.Origin.LastRequestTo(BearerRouteHarness.ResourceMetadataPath);

        _post = await client.SendAsync(new HttpRequestMessage(HttpMethod.Post, BearerRouteHarness.ResourceMetadataPath));
    }

    public Task DisposeAsync()
    {
        _response?.Dispose();
        _post?.Dispose();
        return Task.CompletedTask;
    }

    [Fact] public void should_answer_with_the_origin_response() => Assert.Equal(HttpStatusCode.OK, _response!.StatusCode);
    [Fact] public void should_forward_it() => Assert.NotNull(_forwarded);
    [Fact] public void should_forward_no_principal() => Assert.False(_forwarded!.Has(Headers.PrincipalId));
    [Fact] public void should_forward_no_tenant() => Assert.False(_forwarded!.Has(Headers.TenantId));
    [Fact] public void should_only_serve_reads() => Assert.Equal(HttpStatusCode.MethodNotAllowed, _post!.StatusCode);
}
