// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Scenarios.when_anonymous_paths_are_configured;

/// <summary>
/// End-to-end: two services declaring the same prefix must still serve it.
/// <para>
/// The declared routes carry no service-selection header or query match, so two declarations of the same
/// prefix are two routes ASP.NET cannot choose between — <c>AmbiguousMatchException</c>, surfacing as
/// <c>500</c> on the declared path. Nothing reports it at startup; the first anonymous caller finds it.
/// A <c>502</c> here is the proof the request was forwarded to a real destination rather than dying in
/// route selection.
/// </para>
/// </summary>
/// <param name="factory">The shared application factory.</param>
public class and_two_services_declare_the_same_path(SharedPrefixAuthProxyFactory factory)
    : IClassFixture<SharedPrefixAuthProxyFactory>, IAsyncLifetime
{
    HttpResponseMessage? _shared;
    HttpResponseMessage? _sharedChild;

    public async Task InitializeAsync()
    {
        using var client = factory.CreateTestClient();

        _shared = await client.GetAsync(AuthProxyFactory.AnonymousFrontendPath);
        _sharedChild = await client.GetAsync($"{AuthProxyFactory.AnonymousFrontendPath}/some-token");
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_forward_the_shared_prefix() => Assert.Equal(HttpStatusCode.BadGateway, _shared!.StatusCode);
    [Fact] public void should_forward_below_the_shared_prefix() => Assert.Equal(HttpStatusCode.BadGateway, _sharedChild!.StatusCode);
}
