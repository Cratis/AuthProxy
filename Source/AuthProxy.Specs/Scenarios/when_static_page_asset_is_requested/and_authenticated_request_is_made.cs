// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Scenarios.when_static_page_asset_is_requested;

public class and_authenticated_request_is_made(AuthProxyFactory factory) : IClassFixture<AuthProxyFactory>, IAsyncLifetime
{
    HttpResponseMessage? _response;
    string? _responseBody;

    public async Task InitializeAsync()
    {
        using var client = factory.CreateTestClient(authenticated: true);
        _response = await client.GetAsync("/_pages/logo.svg");
        _responseBody = await _response.Content.ReadAsStringAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_return_200() => Assert.Equal(System.Net.HttpStatusCode.OK, _response.StatusCode);
    [Fact] public void should_return_the_static_asset() => Assert.Contains("<svg", _responseBody);
}