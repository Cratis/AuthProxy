// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

/// <summary>
/// A bearer route is called by programs. Without a token the answer is an RFC 6750 challenge naming the RFC 9728
/// resource metadata an MCP client discovers its authorization server from — never a redirect to provider
/// selection, and never a browser session standing in for the missing token.
/// </summary>
/// <param name="harness">The running proxy, origin and issuer.</param>
[Collection(BearerRouteSpecCollection.Name)]
public class when_no_token_is_presented(BearerRouteHarness harness) : IAsyncLifetime
{
    const string Path = $"{BearerRouteHarness.RoutePrefix}/tools";

    HttpResponseMessage? _anonymous;
    HttpResponseMessage? _withSession;
    bool _forwarded;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateBearerClient();
        harness.Origin.Clear();

        _anonymous = await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, Path));
        _withSession = await client.SendAsync(SecurityHarness.Authenticated(HttpMethod.Get, Path));
        _forwarded = harness.Origin.ReceivedAnythingFor(Path);
    }

    public Task DisposeAsync()
    {
        _anonymous?.Dispose();
        _withSession?.Dispose();
        return Task.CompletedTask;
    }

    [Fact] public void should_refuse_as_unauthorized() => Assert.Equal(HttpStatusCode.Unauthorized, _anonymous!.StatusCode);
    [Fact] public void should_challenge_with_the_resource_metadata() =>
        Assert.Equal($"Bearer resource_metadata=\"{BearerRouteHarness.ResourceMetadataUrl}\"", _anonymous!.Headers.WwwAuthenticate.ToString());
    [Fact] public void should_not_let_a_browser_session_stand_in_for_the_token() => Assert.Equal(HttpStatusCode.Unauthorized, _withSession!.StatusCode);
    [Fact] public void should_not_forward_anything() => Assert.False(_forwarded);
    [Fact] public void should_not_be_cached() => Assert.True(_anonymous!.Headers.CacheControl?.NoStore);
}
