// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Scenarios.when_anonymous_paths_are_configured;

/// <summary>
/// End-to-end: a declared anonymous path must be forwarded for a signed-in caller who has not chosen a
/// tenant, not answered with the tenant-selection page.
/// <para>
/// Provider selection and the unresolved-tenant refusal are both skipped for a caller with no session at
/// all, which leaves tenant selection as the one enforcement point an <em>authenticated</em> caller still
/// meets. A path is declared anonymous because the application serves it without regard to who is asking —
/// a magic-link report, a public webhook receiver — and it does not become unreachable because the caller
/// happens to also have a session open in the same browser.
/// </para>
/// <para>
/// The undeclared path is the control: it must still be answered with the tenant chooser, which is what
/// shows the skip is scoped to the declared prefixes rather than disabling tenant selection.
/// </para>
/// </summary>
/// <param name="factory">The shared application factory.</param>
public class and_the_caller_is_signed_in_without_a_tenant(TenantSelectionAuthProxyFactory factory)
    : IClassFixture<TenantSelectionAuthProxyFactory>, IAsyncLifetime
{
    HttpResponseMessage? _declaredFrontend;
    HttpResponseMessage? _declaredBackend;
    HttpResponseMessage? _undeclared;
    string? _undeclaredBody;

    public async Task InitializeAsync()
    {
        using var client = factory.CreateTestClient();

        _declaredFrontend = await client.GetAsync(AuthProxyFactory.AnonymousFrontendPath);
        _declaredBackend = await client.GetAsync(AuthProxyFactory.AnonymousBackendPath);

        _undeclared = await client.SendAsync(AuthProxyFactory.BrowserNavigation("/dashboard"));
        _undeclaredBody = await _undeclared.Content.ReadAsStringAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_forward_the_declared_frontend_path() => Assert.Equal(HttpStatusCode.BadGateway, _declaredFrontend!.StatusCode);
    [Fact] public void should_forward_the_declared_backend_path() => Assert.Equal(HttpStatusCode.BadGateway, _declaredBackend!.StatusCode);

    [Fact] public void should_still_select_a_tenant_for_an_undeclared_path() => Assert.Contains("Select Tenant", _undeclaredBody);
}
