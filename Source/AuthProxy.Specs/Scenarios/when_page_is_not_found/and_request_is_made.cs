// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Scenarios.when_page_is_not_found;

/// <summary>
/// Verifies that requests for paths that do not match any configured route result in a 404 response.
/// </summary>
/// <param name="factory">The shared application factory.</param>
public class and_request_is_made(AuthProxyFactory factory) : IClassFixture<AuthProxyFactory>, IAsyncLifetime
{
    HttpResponseMessage? _response;

    public async Task InitializeAsync()
    {
        using var client = factory.CreateTestClient(authenticated: true);
        _response = await client.GetAsync("/this/path/does/not/exist");
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_return_404() => Assert.Equal(System.Net.HttpStatusCode.NotFound, _response.StatusCode);
}
