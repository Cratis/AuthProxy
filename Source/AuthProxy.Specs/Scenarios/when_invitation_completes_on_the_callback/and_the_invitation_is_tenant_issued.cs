// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Scenarios.when_invitation_completes_on_the_callback;

/// <summary>
/// End-to-end scenario: the invitation was issued by the tenant the request is served for, so a completed
/// invitation does not leave for the lobby — the exchange still runs on the callback, but the browser is
/// redirected to the challenge's own return URL exactly as any other sign-in would be.
/// </summary>
/// <param name="factory">The shared application factory.</param>
public class and_the_invitation_is_tenant_issued(CallbackAuthProxyFactory factory) : IClassFixture<CallbackAuthProxyFactory>, IAsyncLifetime
{
    string _token;
    CallbackAuthProxyFactory.ProviderSignIn _signIn;
    int _exchangeCallsDuringFlow;

    public async Task InitializeAsync()
    {
        _token = TokenFixture.CreateToken(
            factory.InviteKeyPair.PrivateKey,
            additionalClaims:
            [
                new Claim("jti", Guid.NewGuid().ToString()),
                new Claim(CallbackAuthProxyFactory.TenantClaim, CallbackAuthProxyFactory.TenantId),
            ]);

        using var browser = factory.CreateBrowser();
        var exchangeCallsBefore = factory.ExchangeCallCount;
        _signIn = await factory.SignInThroughProvider(browser, $"/invite/{_token}");
        _exchangeCallsDuringFlow = factory.ExchangeCallCount - exchangeCallsBefore;
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void should_call_the_exchange_endpoint_on_the_callback() =>
        Assert.Equal(1, _exchangeCallsDuringFlow);

    [Fact]
    public void should_preserve_the_return_url() =>
        Assert.Equal($"/invite/{_token}", _signIn.Callback.Headers.Location?.ToString());

    [Fact]
    public void should_establish_the_session()
    {
        Assert.Contains(
            _signIn.CallbackCookies,
            cookie => cookie.StartsWith(CallbackAuthProxyFactory.SessionCookieName, StringComparison.Ordinal));
    }

    [Fact]
    public void should_delete_the_pending_invitation_cookie()
    {
        _signIn.Callback.Headers.TryGetValues("Set-Cookie", out var cookies);
        Assert.Contains(
            cookies ?? [],
            cookie => cookie.StartsWith($"{Cookies.InviteToken}=;", StringComparison.Ordinal));
    }
}
