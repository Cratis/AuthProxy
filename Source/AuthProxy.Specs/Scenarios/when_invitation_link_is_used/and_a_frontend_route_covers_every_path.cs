// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Scenarios.when_invitation_link_is_used;

/// <summary>
/// Pins that a deployment whose frontend catch-all route covers every path still answers an invitation with
/// the invitation flow.
/// </summary>
/// <remarks>
/// The catch-all is generated with the default authorization policy — <c>RequireAuthenticatedUser</c> — and
/// the invite middleware is registered after <c>UseAuthorization</c>. Without releasing the proxy-owned
/// flows from the route that matched them, authorization refused the request first and redirected the
/// browser to provider selection: no invitation staged, and no pending-invitation cookie, so the sign-in
/// that followed carried no capability binding and the invitation could only complete on a later pass.
/// Landing on a provider-selection page either way is what made this so easy to miss — the assertion that
/// separates the two is the pending-invitation cookie, which only the invite flow plants.
/// </remarks>
/// <param name="factory">The single-service, frontend-routed proxy this scenario runs against.</param>
public class and_a_frontend_route_covers_every_path(FrontendRoutedAuthProxyFactory factory)
    : IClassFixture<FrontendRoutedAuthProxyFactory>, IAsyncLifetime
{
    HttpResponseMessage? _response;
    HttpResponseMessage? _registration;
    string? _responseBody;

    public async Task InitializeAsync()
    {
        var token = TokenFixture.CreateToken(
            factory.InviteKeyPair.PrivateKey,
            additionalClaims: [new Claim("jti", Guid.NewGuid().ToString())]);

        using var client = factory.CreateTestClient();
        _response = await client.GetAsync($"/invite/{token}");
        _responseBody = await _response.Content.ReadAsStringAsync();
        _registration = await client.GetAsync("/register");
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void should_not_redirect_the_invitation_to_the_login_page() =>
        Assert.NotEqual(HttpStatusCode.Redirect, _response.StatusCode);

    [Fact]
    public void should_serve_the_invitation_provider_selection_page() =>
        Assert.Contains("Select Provider", _responseBody);

    [Fact]
    public void should_return_200_for_the_invitation() =>
        Assert.Equal(HttpStatusCode.OK, _response.StatusCode);

    [Fact]
    public void should_stage_the_invitation_by_setting_the_pending_invitation_cookie()
    {
        _response.Headers.TryGetValues("Set-Cookie", out var cookies);
        Assert.True(
            cookies?.Any(_ => _.StartsWith(Cookies.InviteToken, StringComparison.OrdinalIgnoreCase)),
            $"Expected Set-Cookie header containing '{Cookies.InviteToken}' — without it the sign-in that follows carries no capability binding");
    }

    [Fact]
    public void should_not_redirect_registration_to_the_login_page() =>
        Assert.NotEqual(HttpStatusCode.Redirect, _registration.StatusCode);
}
