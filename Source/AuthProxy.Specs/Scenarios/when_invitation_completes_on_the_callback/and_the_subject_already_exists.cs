// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.Invites;

namespace Cratis.AuthProxy.Scenarios.when_invitation_completes_on_the_callback;

/// <summary>
/// End-to-end scenario: the exchange on the callback answers with a conflict — the authenticated subject
/// already belongs to an existing user. The callback produces the same outcome the post-login exchange
/// produces today: the pending invitation is cleared and the signed-in browser is redirected to the
/// configured subject-already-exists page.
/// </summary>
/// <param name="factory">The shared application factory.</param>
public class and_the_subject_already_exists(CallbackAuthProxyFactory factory) : IClassFixture<CallbackAuthProxyFactory>, IAsyncLifetime
{
    CallbackAuthProxyFactory.ProviderSignIn _signIn;
    int _exchangeCallsDuringFlow;

    public async Task InitializeAsync()
    {
        factory.ExchangeStatusCode = HttpStatusCode.Conflict;
        var token = TokenFixture.CreateToken(
            factory.InviteKeyPair.PrivateKey,
            additionalClaims: [new Claim("jti", Guid.NewGuid().ToString())]);

        using var browser = factory.CreateBrowser();
        var exchangeCallsBefore = factory.ExchangeCallCount;
        _signIn = await factory.SignInThroughProvider(browser, $"/invite/{token}");
        _exchangeCallsDuringFlow = factory.ExchangeCallCount - exchangeCallsBefore;
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void should_call_the_exchange_endpoint_on_the_callback() =>
        Assert.Equal(1, _exchangeCallsDuringFlow);

    [Fact]
    public void should_redirect_to_the_subject_already_exists_page() =>
        Assert.Equal(CallbackAuthProxyFactory.SubjectAlreadyExistsUrl, _signIn.Callback.Headers.Location?.ToString());

    [Fact]
    public void should_still_establish_the_session()
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
