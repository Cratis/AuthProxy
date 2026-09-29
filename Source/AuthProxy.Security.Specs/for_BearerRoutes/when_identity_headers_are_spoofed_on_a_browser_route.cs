// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

/// <summary>
/// The token headers mean "authenticated on a bearer route", so only a bearer route may send them. On a browser
/// route a caller's own copies are removed with every other identity header, and the principal forwarded is the
/// session's.
/// </summary>
/// <param name="harness">The running proxy, origin and issuer.</param>
[Collection(BearerRouteSpecCollection.Name)]
public class when_identity_headers_are_spoofed_on_a_browser_route(BearerRouteHarness harness) : IAsyncLifetime
{
    const string Path = "/api/spoofed";

    HttpResponseMessage? _response;
    ForwardedRequest? _forwarded;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateBearerClient();
        harness.Origin.Clear();

        var request = SecurityHarness.Authenticated(HttpMethod.Get, Path, "browser-user");
        request.Headers.TryAddWithoutValidation(Headers.TokenScope, "direct:admin");
        request.Headers.TryAddWithoutValidation(Headers.TokenClientId, "trusted-client");
        request.Headers.TryAddWithoutValidation(Headers.PrincipalId, "attacker");
        request.Headers.TryAddWithoutValidation(Headers.TenantId, "victim-tenant");

        _response = await client.SendAsync(request);
        _forwarded = harness.Origin.LastRequestTo(Path);
    }

    public Task DisposeAsync()
    {
        _response?.Dispose();
        return Task.CompletedTask;
    }

    [Fact] public void should_forward_the_request() => Assert.NotNull(_forwarded);
    [Fact] public void should_not_forward_the_scope_header() => Assert.False(_forwarded!.Has(Headers.TokenScope));
    [Fact] public void should_not_forward_the_client_header() => Assert.False(_forwarded!.Has(Headers.TokenClientId));
    [Fact] public void should_forward_the_session_principal() => Assert.Equal("browser-user", _forwarded!.Value(Headers.PrincipalId));
    [Fact] public void should_forward_the_session_tenant() => Assert.Equal(BearerRouteHarness.SessionTenantId, _forwarded!.Value(Headers.TenantId));
}
