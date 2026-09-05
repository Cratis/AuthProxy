// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Scenarios.when_invitation_completes_on_the_callback;

/// <summary>
/// End-to-end scenario: a signed matching-tenant invitation completes once on the provider callback and establishes
/// one session, while the Lobby destination policy sends the browser to Lobby instead of replaying the invite URL.
/// </summary>
/// <param name="factory">The signed invitation callback factory with matching-tenant destination set to Lobby.</param>
public class and_the_matching_tenant_destination_is_lobby(MatchingTenantLobbyRedirectCallbackAuthProxyFactory factory) :
    IClassFixture<MatchingTenantLobbyRedirectCallbackAuthProxyFactory>, IAsyncLifetime
{
    string _invitationId;
    CallbackAuthProxyFactory.ProviderSignIn _signIn;
    int _exchangeCallsDuringFlow;

    public async Task InitializeAsync()
    {
        _invitationId = Guid.NewGuid().ToString();
        var token = TokenFixture.CreateToken(
            factory.InviteKeyPair.PrivateKey,
            additionalClaims:
            [
                new Claim("jti", _invitationId),
                new Claim(CallbackAuthProxyFactory.TenantClaim, CallbackAuthProxyFactory.TenantId),
                new Claim("email", "invitee@example.com"),
            ]);

        using var browser = factory.CreateBrowser();
        var exchangeCallsBefore = factory.ExchangeCallCount;
        _signIn = await factory.SignInThroughProvider(browser, $"/invite/{token}");
        _exchangeCallsDuringFlow = factory.ExchangeCallCount - exchangeCallsBefore;
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void should_stage_the_signed_invitation() =>
        Assert.Contains(
            _signIn.ChallengeCookies,
            cookie => cookie.StartsWith($"{Cookies.InvitationEntryState}=", StringComparison.Ordinal));

    [Fact]
    public void should_call_the_attested_completion_endpoint_once() =>
        Assert.Equal(1, _exchangeCallsDuringFlow);

    [Fact]
    public void should_establish_one_session() =>
        Assert.Single(
            _signIn.CallbackCookies,
            cookie => cookie.StartsWith(CallbackAuthProxyFactory.SessionCookieName, StringComparison.Ordinal));

    [Fact]
    public void should_redirect_the_callback_to_lobby() =>
        Assert.Equal(
            $"{CallbackAuthProxyFactory.LobbyUrl}?invitationId={_invitationId}",
            _signIn.Callback.Headers.Location?.ToString());
}
