// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Scenarios.when_invitation_link_is_used;

public class and_token_metadata_is_configured_but_unreachable(MetadataAuthProxyFactory factory) : IClassFixture<MetadataAuthProxyFactory>, IAsyncLifetime
{
    HttpResponseMessage _response;
    string _body;

    public async ValueTask InitializeAsync()
    {
        factory.MetadataUnavailable = true;
        var token = TokenFixture.CreateToken(factory.InviteKeyPair.PrivateKey, MetadataAuthProxyFactory.Issuer, MetadataAuthProxyFactory.Audience);
        using var client = factory.CreateTestClient();
        _response = await client.GetAsync($"/invite/{token}");
        _body = await _response.Content.ReadAsStringAsync();
    }
    public ValueTask DisposeAsync()
    {
        _response.Dispose();
        return ValueTask.CompletedTask;
    }
    [Fact] public void should_fail_closed() => Assert.Equal(HttpStatusCode.Unauthorized, _response.StatusCode);
    [Fact] public void should_show_the_invalid_invitation_page() => Assert.Contains("Invitation Invalid", _body, StringComparison.Ordinal);
    [Fact] public void should_not_call_exchange() => Assert.Equal(0, factory.ExchangeCallCount);
}
