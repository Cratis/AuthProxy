// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Scenarios.when_invitation_link_is_used;

public class and_token_metadata_is_configured(MetadataAuthProxyFactory factory) : IClassFixture<MetadataAuthProxyFactory>, IAsyncLifetime
{
    HttpResponseMessage _response;

    public async ValueTask InitializeAsync()
    {
        var token = TokenFixture.CreateToken(factory.InviteKeyPair.PrivateKey, MetadataAuthProxyFactory.Issuer, MetadataAuthProxyFactory.Audience, additionalClaims: [new Claim("jti", Guid.NewGuid().ToString())]);
        using var client = factory.CreateTestClient(authenticated: true, inviteTokenCookie: token);
        _response = await client.GetAsync("/");
    }
    public ValueTask DisposeAsync()
    {
        _response.Dispose();
        return ValueTask.CompletedTask;
    }
    [Fact] public void should_redirect_to_lobby() => Assert.Equal(AuthProxyFactory.LobbyUrl, _response.Headers.Location?.ToString());
    [Fact] public void should_complete_the_invitation() => Assert.True(factory.ExchangeCallCount > 0);
    [Fact] public void should_resolve_identity() => Assert.True(factory.IdentityCallCount > 0);
    [Fact] public void should_answer_with_a_redirect() => Assert.Equal(HttpStatusCode.Redirect, _response.StatusCode);
    [Fact] public void should_set_identity_and_clear_the_invitation()
    {
        var cookies = _response.Headers.GetValues("Set-Cookie");
        Assert.Contains(cookies, cookie => cookie.StartsWith(Cookies.Identity, StringComparison.Ordinal));
        Assert.Contains(cookies, cookie => cookie.StartsWith(Cookies.InviteToken, StringComparison.Ordinal));
    }
}
