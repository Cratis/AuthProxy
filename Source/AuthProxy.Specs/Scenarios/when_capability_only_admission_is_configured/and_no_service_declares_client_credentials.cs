// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Scenarios.when_capability_only_admission_is_configured;

/// <summary>
/// The client-credentials token endpoint is not in this deployment's routing table at all.
/// <para>
/// It is mapped unconditionally today, including where no service declares client credentials and it can
/// therefore only ever refuse — and a refusal from it is still an answer, naming an AuthProxy as the thing
/// answering. Refusing it through the gate would not be enough either: an endpoint that exists is an
/// endpoint a later change can accidentally reach, so a closed deployment with nothing to grant does not
/// have one.
/// </para>
/// <para>
/// Asserted against the routing table rather than against a response, because a <c>404</c> is what the gate
/// answers to everything and would say nothing about whether the route was ever declared.
/// </para>
/// </summary>
/// <param name="factory">The closed proxy under test.</param>
public class and_no_service_declares_client_credentials(AuthProxyFactory factory) : IClassFixture<AuthProxyFactory>, IAsyncLifetime
{
    string[] _routes = [];

    public Task InitializeAsync()
    {
        using var client = factory.CreateProbingClient();

        _routes =
        [
            .. factory.Services.GetRequiredService<EndpointDataSource>()
                .Endpoints
                .OfType<RouteEndpoint>()
                .Select(endpoint => endpoint.RoutePattern.RawText ?? string.Empty)
        ];

        return Task.CompletedTask;
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void should_leave_the_token_endpoint_out_of_the_routing_table() =>
        Assert.DoesNotContain(WellKnownPaths.Token, _routes, StringComparer.OrdinalIgnoreCase);

    [Fact]
    public void should_still_declare_the_endpoints_the_deployment_does_have() =>
        Assert.Contains(WellKnownPaths.Providers, _routes, StringComparer.OrdinalIgnoreCase);
}
