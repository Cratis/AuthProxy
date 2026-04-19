// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Scenarios.when_multiple_providers_are_configured;

/// <summary>
/// End-to-end scenario: an unauthenticated user requests any page when multiple OIDC providers
/// are configured. Verifies that SelectProviderMiddleware intercepts the request, sets the
/// providers cookie, and serves the select-provider page.
/// </summary>
/// <param name="factory">The shared application factory.</param>
public class and_unauthenticated_user_requests_page(AuthProxyFactory factory) : IClassFixture<AuthProxyFactory>, IAsyncLifetime
{
    HttpResponseMessage? _response;
    string? _responseBody;

    public async Task InitializeAsync()
    {
        using var client = factory.CreateTestClient();
        _response = await client.GetAsync("/");
        _responseBody = await _response.Content.ReadAsStringAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_return_200() => Assert.Equal(System.Net.HttpStatusCode.OK, _response!.StatusCode);
    [Fact] public void should_return_html() => Assert.Equal("text/html; charset=utf-8", _response!.Content.Headers.ContentType?.ToString());
    [Fact] public void should_return_select_provider_page() => Assert.Contains("Select Provider", _responseBody);

    [Fact]
    public void should_set_providers_cookie()
    {
        _response!.Headers.TryGetValues("Set-Cookie", out var cookies);
        Assert.True(
            cookies?.Any(c => c.StartsWith(Cookies.Providers, StringComparison.OrdinalIgnoreCase)),
            $"Expected Set-Cookie header containing '{Cookies.Providers}'");
    }
}
