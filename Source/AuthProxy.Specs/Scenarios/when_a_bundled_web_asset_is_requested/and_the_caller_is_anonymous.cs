// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Scenarios.when_a_bundled_web_asset_is_requested;

/// <summary>
/// Regression coverage for a bundled <c>wwwroot</c> asset (e.g. the login-selection SPA's own script)
/// being refused instead of served once the reverse proxy has a real backend configured. Without an
/// explicit <c>UseRouting()</c> anchored after <c>UseStaticFiles()</c>, ASP.NET Core's implicit routing
/// insertion matches the reverse proxy's catch-all route before static files run, and
/// <c>UseStaticFiles</c> — being endpoint-aware — skips a request that already carries a matched endpoint.
/// The request then falls through to <c>SelectProviderMiddleware</c>, which refuses every unauthenticated,
/// non-navigating caller with a <c>401</c>, so the asset never loads and the page it belongs to renders
/// blank.
/// </summary>
/// <param name="factory">The proxy under test, with a real backend route and a bundled asset.</param>
public class and_the_caller_is_anonymous(AuthProxyFactory factory) : IClassFixture<AuthProxyFactory>, IAsyncLifetime
{
    HttpResponseMessage? _response;
    string? _responseBody;

    public async Task InitializeAsync()
    {
        using var client = factory.CreateAnonymousClient();
        _response = await client.GetAsync(AuthProxyFactory.AssetPath);
        _responseBody = await _response.Content.ReadAsStringAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_return_200() => Assert.Equal(System.Net.HttpStatusCode.OK, _response!.StatusCode);
    [Fact] public void should_return_the_asset_content() => Assert.Equal(AuthProxyFactory.AssetContent, _responseBody);
}
