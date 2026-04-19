// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Scenarios.when_invitation_link_is_used;

namespace Cratis.AuthProxy.Scenarios.when_page_is_not_found;

/// <summary>
/// Verifies that requests for paths that do not match any configured route result in a 404 response.
/// YARP returns 404 when no route matches the request.
/// </summary>
public class and_request_is_made(AuthProxyFactory factory) : IClassFixture<AuthProxyFactory>, IAsyncLifetime
{
    HttpResponseMessage? _response;

    public async Task InitializeAsync()
    {
        using var client = factory.CreateTestClient();
        _response = await client.GetAsync("/this/path/does/not/exist");
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_return_404() => Assert.Equal(System.Net.HttpStatusCode.NotFound, _response.StatusCode);
}
