// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Scenarios.when_signing_in_with_a_code;

public class and_the_sign_in_answers_an_invitation(InvitationAuthProxyFactory factory) : IClassFixture<InvitationAuthProxyFactory>, IAsyncLifetime
{
    readonly string _invited = AuthProxyFactory.NewKnownAddress();
    HttpResponseMessage _invite = null!;
    string _addressPage = string.Empty;
    string _codePage = string.Empty;

    public async ValueTask InitializeAsync()
    {
        using var client = factory.CreateTestClient();
        _invite = await client.SendAsync(new HttpRequestMessage(HttpMethod.Get, $"/invite/{factory.InvitationFor(_invited)}") { Headers = { { "Sec-Fetch-Dest", "document" } } });
        if (_invite.Headers.Location is null)
        {
            throw new InvalidOperationException($"{(int)_invite.StatusCode} {await _invite.Content.ReadAsStringAsync()}");
        }

        using var page = await client.GetAsync(_invite.Headers.Location);
        _addressPage = await page.Content.ReadAsStringAsync();
        _codePage = await AuthProxyFactory.Request(client, AuthProxyFactory.Field(_addressPage, "state"), "someone-else@example.com");
    }

    public ValueTask DisposeAsync()
    {
        _invite.Dispose();
        return ValueTask.CompletedTask;
    }

    [Fact] void should_show_the_invited_address_locked() => Assert.Contains($"value=\"{_invited}\"", _addressPage);
    [Fact] void should_lock_the_address() => Assert.Contains("readonly", _addressPage);
    [Fact] void should_ask_for_an_invitation_code() => Assert.Equal("invitation", factory.Delivery.For(_invited).Purpose);
    [Fact] void should_name_the_invitation() => Assert.Equal("9f6b3c0a-0000-4000-8000-000000000001", factory.Delivery.For(_invited).InvitationId);
    [Fact] void should_ignore_an_address_typed_into_a_bound_invitation() => Assert.Equal(0, factory.Delivery.CountFor("someone-else@example.com"));
    [Fact] void should_show_the_code_page() => Assert.Contains("Enter your code", _codePage);
}
