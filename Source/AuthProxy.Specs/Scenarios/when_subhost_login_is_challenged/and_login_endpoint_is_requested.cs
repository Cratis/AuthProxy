// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.Scenarios.when_subhost_login_is_challenged;

/// <summary>
/// End-to-end scenario: when login is initiated from a subhost tenant request, the emitted
/// OAuth state contains tenant and strategy metadata.
/// </summary>
/// <param name="factory">The shared application factory.</param>
public class and_login_endpoint_is_requested(AuthProxyFactory factory) : IClassFixture<AuthProxyFactory>, IAsyncLifetime
{
    HttpResponseMessage? _response;

    public async Task InitializeAsync()
    {
        using var client = factory.CreateTestClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, $"/.cratis/login/{AuthProxyFactory.ProviderScheme}?returnUrl=%2Fdashboard");
        request.Headers.Host = "nova.cratis.studio";

        _response = await client.SendAsync(request);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_redirect_to_authorization_endpoint() => Assert.Equal(System.Net.HttpStatusCode.Redirect, _response!.StatusCode);

    [Fact] public void should_challenge_with_provider_scheme() => Assert.Equal(AuthProxyFactory.ProviderScheme, factory.CapturedScheme);

    [Fact]
    public void should_capture_return_url_as_redirect_uri() =>
        Assert.Equal("/dashboard", factory.CapturedProperties!.RedirectUri);

    [Fact]
    public void should_include_tenant_id_in_state() =>
        Assert.Equal("nova", factory.CapturedProperties!.Items[TenantAuthenticationState.TenantIdStateKey]);

    [Fact]
    public void should_include_subhost_strategy_in_state() =>
        Assert.Equal(nameof(C.TenantSourceIdentifierResolverType.SubHost), factory.CapturedProperties!.Items[TenantAuthenticationState.StrategyStateKey]);

    [Fact]
    public void should_include_subhost_parent_host_in_state() =>
        Assert.Equal(AuthProxyFactory.ParentHost, factory.CapturedProperties!.Items[TenantAuthenticationState.SubHostParentHostStateKey]);
}