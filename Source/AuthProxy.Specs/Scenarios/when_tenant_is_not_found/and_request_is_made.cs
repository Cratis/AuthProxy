// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Scenarios.when_tenant_is_not_found;

public class and_request_is_made(AuthProxyFactory factory) : IClassFixture<AuthProxyFactory>, IAsyncLifetime
{
    HttpResponseMessage? _response;
    string? _responseBody;

    public async Task InitializeAsync()
    {
        using var client = factory.CreateTestClient(authenticated: true);
        _response = await client.GetAsync("/");
        _responseBody = await _response.Content.ReadAsStringAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_return_404() => Assert.Equal(System.Net.HttpStatusCode.NotFound, _response.StatusCode);
    [Fact] public void should_return_html() => Assert.Equal("text/html; charset=utf-8", _response.Content.Headers.ContentType?.ToString());
    [Fact] public void should_return_tenant_not_found_page() => Assert.Contains("Tenant Not Found", _responseBody);
}
