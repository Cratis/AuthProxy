// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Scenarios.when_invitation_link_is_used;

public class and_token_is_wrong(AuthProxyFactory factory) : IClassFixture<AuthProxyFactory>, IAsyncLifetime
{
    HttpResponseMessage? _response;
    string? _responseBody;

    public async Task InitializeAsync()
    {
        using var client = factory.CreateTestClient();
        _response = await client.GetAsync("/invite/this-is-not-a-jwt");
        _responseBody = await _response.Content.ReadAsStringAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_return_401() => Assert.Equal(System.Net.HttpStatusCode.Unauthorized, _response.StatusCode);
    [Fact] public void should_not_call_exchange_endpoint() => Assert.Equal(0, factory.ExchangeCallCount);
    [Fact] public void should_return_invitation_invalid_page() => Assert.Contains("Invitation Invalid", _responseBody);
}
