// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Scenarios.when_invitation_link_is_used;

public class and_multiple_providers_are_configured(MultipleProvidersAuthProxyFactory factory) : IClassFixture<MultipleProvidersAuthProxyFactory>, IAsyncLifetime
{
    HttpResponseMessage? _response;
    string? _responseBody;

    public async Task InitializeAsync()
    {
        var token = TokenFixture.CreateToken(
            factory.InviteKeyPair.PrivateKey,
            additionalClaims: [new Claim("jti", Guid.NewGuid().ToString())]);

        using var client = factory.CreateTestClient();
        _response = await client.GetAsync($"/invite/{token}");
        _responseBody = await _response.Content.ReadAsStringAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_return_200() => Assert.Equal(System.Net.HttpStatusCode.OK, _response.StatusCode);
    [Fact] public void should_return_html() => Assert.Equal("text/html; charset=utf-8", _response.Content.Headers.ContentType?.ToString());
    [Fact] public void should_return_select_provider_page() => Assert.Contains("Select Provider", _responseBody);

    [Fact]
    public void should_set_providers_cookie()
    {
        _response.Headers.TryGetValues("Set-Cookie", out var cookies);
        Assert.True(
            cookies?.Any(c => c.StartsWith(Cookies.Providers, StringComparison.OrdinalIgnoreCase)),
            $"Expected Set-Cookie header containing '{Cookies.Providers}'");
    }

    [Fact]
    public void should_set_invite_token_cookie()
    {
        _response.Headers.TryGetValues("Set-Cookie", out var cookies);
        Assert.True(
            cookies?.Any(c => c.StartsWith(Cookies.InviteToken, StringComparison.OrdinalIgnoreCase)),
            $"Expected Set-Cookie header containing '{Cookies.InviteToken}'");
    }
}
