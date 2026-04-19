// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Scenarios.when_invitation_link_is_used;

public class and_token_is_wrong : IClassFixture<AuthProxyFactory>, IAsyncLifetime
{
    readonly AuthProxyFactory _factory;
    HttpResponseMessage _response = null!;

    public and_token_is_wrong(AuthProxyFactory factory) => _factory = factory;

    public async Task InitializeAsync()
    {
        using var client = _factory.CreateTestClient();
        _response = await client.GetAsync("/invite/this-is-not-a-jwt");
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_return_401() => Assert.Equal(System.Net.HttpStatusCode.Unauthorized, _response.StatusCode);
    [Fact] public void should_not_call_exchange_endpoint() => Assert.Equal(0, _factory.ExchangeCallCount);
}
