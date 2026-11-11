// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

/// <summary>
/// A token issued for another resource server is not a credential here, even from the same issuer: the audience
/// is what binds a token to the resource it was granted for.
/// </summary>
/// <param name="harness">The running proxy, origin and issuer.</param>
[Collection(BearerRouteSpecCollection.Name)]
public class when_the_token_is_for_another_audience(BearerRouteHarness harness) : IAsyncLifetime
{
    const string Path = $"{BearerRouteHarness.RoutePrefix}/tools";

    HttpResponseMessage? _response;

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateBearerClient();
        harness.Origin.Clear();

        _response = await client.SendAsync(BearerRouteHarness.WithToken(HttpMethod.Get, Path, harness.Issuer.Token(new StubIssuer.TokenRequest { Audience = "studio-api" })));
    }

    public ValueTask DisposeAsync()
    {
        _response?.Dispose();
        return ValueTask.CompletedTask;
    }

    [Fact] public void should_refuse_it() => Assert.Equal(HttpStatusCode.Unauthorized, _response!.StatusCode);
    [Fact] public void should_not_forward_anything() => Assert.Empty(harness.Origin.Received);
    [Fact] public async Task should_return_only_the_machine_readable_error() => Assert.Equal("{\"error\":\"unauthorized\"}", await _response!.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    [Fact] public void should_not_return_a_principal() => Assert.False(_response!.Headers.Contains(Headers.Principal));
    [Fact] public void should_not_return_a_tenant() => Assert.False(_response!.Headers.Contains(Headers.TenantId));
    [Fact] public void should_challenge_with_invalid_token() =>
        Assert.Equal($"Bearer error=\"invalid_token\", resource_metadata=\"{BearerRouteHarness.ResourceMetadataUrl}\"", _response!.Headers.WwwAuthenticate.ToString());
}
