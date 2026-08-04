// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Scenarios.when_anonymous_paths_are_configured;

/// <summary>
/// End-to-end in a single-service deployment: the declared prefixes must beat the catch-all route that
/// shape adds.
/// <para>
/// A single-service proxy also emits <c>/{**catch-all}</c> and <c>/api/{**catch-all}</c> carrying the
/// authenticated-user policy, and both overlap every declared prefix. The declared route only wins by
/// being ordered ahead of them; if it lost, the request would be refused by authorization on the catch-all
/// instead — reachable in the deployment shape a single application actually runs, and invisible in a
/// multi-service test.
/// </para>
/// </summary>
/// <param name="factory">The shared application factory.</param>
public class and_a_single_service_is_deployed(SingleServiceAuthProxyFactory factory)
    : IClassFixture<SingleServiceAuthProxyFactory>, IAsyncLifetime
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

    [Fact] public void should_not_forward_an_undeclared_path() => Assert.NotEqual(HttpStatusCode.BadGateway, _undeclared!.StatusCode);
    [Fact] public void should_still_select_provider_for_an_undeclared_path() => Assert.Contains("Select Provider", _undeclaredBody);
}
