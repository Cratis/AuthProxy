// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Scenarios.when_invitation_link_is_used;

/// <summary>
/// End-to-end scenario for the Phase-2 trust boundary: an authenticated caller places a self-crafted,
/// untrusted-signed token in the <c>.cratis-invite</c> cookie (which HTTP-only does not prevent).
/// AuthProxy must re-validate the token at the exchange forward and refuse to hand it to the exchange endpoint.
/// </summary>
/// <param name="factory">The shared application factory.</param>
public class and_forged_token_is_presented_at_exchange(AuthProxyFactory factory)
    : IClassFixture<AuthProxyFactory>, IAsyncLifetime
{
    HttpResponseMessage? _response;
    string? _responseBody;

    public async Task InitializeAsync()
    {
        var (attackerKey, _) = TokenFixture.GenerateKeyPair();
        var forgedToken = TokenFixture.CreateToken(attackerKey);

        using var client = factory.CreateTestClient(authenticated: true, inviteTokenCookie: forgedToken);
        _response = await client.GetAsync("/");
        _responseBody = await _response.Content.ReadAsStringAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_return_401() => Assert.Equal(System.Net.HttpStatusCode.Unauthorized, _response.StatusCode);
    [Fact] public void should_not_call_exchange_endpoint() => Assert.Equal(0, factory.ExchangeCallCount);
    [Fact] public void should_return_invitation_invalid_page() => Assert.Contains("Invitation Invalid", _responseBody);
}
