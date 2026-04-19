// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Scenarios.when_invitation_link_is_used;

public class and_invitation_is_invalid(AuthProxyFactory factory) : IClassFixture<AuthProxyFactory>, IAsyncLifetime
{
    HttpResponseMessage? _response;
    string? _responseBody;

    public async Task InitializeAsync()
    {
        // Token signed by a different (unknown) RSA key — signature validation fails.
        var (wrongKey, _) = TokenFixture.GenerateKeyPair();
        var token = TokenFixture.CreateToken(wrongKey, additionalClaims: [new Claim("jti", Guid.NewGuid().ToString())]);

        using var client = factory.CreateTestClient();
        _response = await client.GetAsync($"/invite/{token}");
        _responseBody = await _response.Content.ReadAsStringAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_return_401() => Assert.Equal(System.Net.HttpStatusCode.Unauthorized, _response.StatusCode);
    [Fact] public void should_return_html() => Assert.Equal("text/html; charset=utf-8", _response.Content.Headers.ContentType?.ToString());
    [Fact] public void should_not_call_exchange_endpoint() => Assert.Equal(0, factory.ExchangeCallCount);
    [Fact] public void should_return_invitation_invalid_page() => Assert.Contains("Invitation Invalid", _responseBody);
}
