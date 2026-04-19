// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;
using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Scenarios.when_invitation_link_is_used;

public class and_invitation_is_invalid : IClassFixture<AuthProxyFactory>, IAsyncLifetime
{
    readonly AuthProxyFactory _factory;
    HttpResponseMessage _response = null!;

    public and_invitation_is_invalid(AuthProxyFactory factory) => _factory = factory;

    public async Task InitializeAsync()
    {
        // Token signed by a different (unknown) RSA key — signature validation fails.
        var (wrongKey, _) = TokenFixture.GenerateKeyPair();
        var token = TokenFixture.CreateToken(wrongKey, additionalClaims: [new Claim("jti", Guid.NewGuid().ToString())]);

        using var client = _factory.CreateTestClient();
        _response = await client.GetAsync($"/invite/{token}");
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_return_401() => Assert.Equal(System.Net.HttpStatusCode.Unauthorized, _response.StatusCode);
    [Fact] public void should_not_call_exchange_endpoint() => Assert.Equal(0, _factory.ExchangeCallCount);
}
