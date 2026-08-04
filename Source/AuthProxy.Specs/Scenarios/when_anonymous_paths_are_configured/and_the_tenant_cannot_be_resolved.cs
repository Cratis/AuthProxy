// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Scenarios.when_anonymous_paths_are_configured;

/// <summary>
/// End-to-end scenario with tenant resolutions configured that cannot resolve for a caller with no
/// session: the declared anonymous paths must still be forwarded rather than refused for having no tenant.
/// <para>
/// The test destinations do not exist, so reaching the forwarder surfaces as <c>502 Bad Gateway</c> — a
/// status only a forwarded request can produce. Without <c>TenancyMiddleware</c>'s anonymous skip these
/// would be <c>401</c> instead: the same closed door as before the feature, one middleware later.
/// </para>
/// </summary>
/// <param name="factory">The shared application factory.</param>
public class and_the_tenant_cannot_be_resolved(UnresolvedTenantAuthProxyFactory factory)
    : IClassFixture<UnresolvedTenantAuthProxyFactory>, IAsyncLifetime
{
    HttpResponseMessage? _declaredFrontend;
    HttpResponseMessage? _declaredFrontendChild;
    HttpResponseMessage? _declaredBackend;
    HttpResponseMessage? _undeclared;
    string? _undeclaredBody;

    public async Task InitializeAsync()
    {
        using var client = factory.CreateTestClient();

        _declaredFrontend = await client.GetAsync(AuthProxyFactory.AnonymousFrontendPath);
        _declaredFrontendChild = await client.GetAsync($"{AuthProxyFactory.AnonymousFrontendPath}/some-token");
        _declaredBackend = await client.GetAsync(AuthProxyFactory.AnonymousBackendPath);

        _undeclared = await client.SendAsync(AuthProxyFactory.BrowserNavigation("/dashboard"));
        _undeclaredBody = await _undeclared.Content.ReadAsStringAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_forward_the_declared_frontend_path() => Assert.Equal(HttpStatusCode.BadGateway, _declaredFrontend!.StatusCode);
    [Fact] public void should_forward_below_the_declared_frontend_path() => Assert.Equal(HttpStatusCode.BadGateway, _declaredFrontendChild!.StatusCode);
    [Fact] public void should_forward_the_declared_backend_path() => Assert.Equal(HttpStatusCode.BadGateway, _declaredBackend!.StatusCode);

    [Fact] public void should_still_select_provider_for_an_undeclared_path() => Assert.Contains("Select Provider", _undeclaredBody);
}
