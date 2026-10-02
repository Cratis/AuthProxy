// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

/// <summary>
/// A token accepted on a bearer route is accepted there and nowhere else. On a browser-only surface such as
/// <c language="text">/api</c> it is refused outright, even alongside a browser session, so an API token can never reach
/// what only a person signed in through the browser may use.
/// </summary>
/// <param name="harness">The running proxy, origin and issuer.</param>
[Collection(BearerRouteSpecCollection.Name)]
public class when_a_bearer_token_is_presented_on_a_browser_route(BearerRouteHarness harness) : IAsyncLifetime
{
    const string Path = "/api/items";

    HttpResponseMessage? _response;
    HttpResponseMessage? _withSession;
    HttpResponseMessage? _sessionOnly;
    bool _forwardedWithToken;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateBearerClient();
        harness.Origin.Clear();

        _response = await client.SendAsync(BearerRouteHarness.WithToken(HttpMethod.Get, Path, harness.Issuer.Token()));

        var withSession = BearerRouteHarness.WithToken(HttpMethod.Get, Path, harness.Issuer.Token());
        withSession.Headers.TryAddWithoutValidation(SecurityHarness.AuthenticatedUserHeader, "bearer-spec-user");
        _withSession = await client.SendAsync(withSession);
        _forwardedWithToken = harness.Origin.ReceivedAnythingFor(Path);

        _sessionOnly = await client.SendAsync(SecurityHarness.Authenticated(HttpMethod.Get, Path, "bearer-spec-user"));
    }

    public Task DisposeAsync()
    {
        _response?.Dispose();
        _withSession?.Dispose();
        _sessionOnly?.Dispose();
        return Task.CompletedTask;
    }

    [Fact] public void should_refuse_it() => Assert.Equal(HttpStatusCode.Unauthorized, _response!.StatusCode);
    [Fact] public void should_refuse_it_alongside_a_browser_session() => Assert.Equal(HttpStatusCode.Unauthorized, _withSession!.StatusCode);
    [Fact] public void should_not_forward_it() => Assert.False(_forwardedWithToken);
    [Fact] public void should_challenge_with_invalid_token() => Assert.Equal("Bearer error=\"invalid_token\"", _response!.Headers.WwwAuthenticate.ToString());
    [Fact] public void should_still_serve_the_browser_session() => Assert.Equal(HttpStatusCode.OK, _sessionOnly!.StatusCode);
}
