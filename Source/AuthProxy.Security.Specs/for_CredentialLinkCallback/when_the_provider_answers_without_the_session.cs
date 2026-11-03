// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_CredentialLinkCallback;

/// <summary>
/// A redirect callback always carries the session cookie, so one without it must not complete the link, even with the flow's own state and correlation cookie.
/// </summary>
/// <param name="harness">The running proxy.</param>
[Collection(SessionCookieSpecCollection.Name)]
public class when_the_provider_answers_without_the_session(SessionCookieHarness harness) : IAsyncLifetime
{
    HttpResponseMessage? _callback;
    bool _exchanged;

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        var browser = new CredentialLinkBrowser(harness);
        var (state, handshake) = await browser.Start(client, await browser.SignIn(client));

        harness.ClearOrigins();
        _callback = await browser.Callback(client, state, handshake);
        _exchanged = harness.ConsoleOrigin.ReceivedAnythingFor(SessionCookieHarness.LinkExchangePath);
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact]
    public void should_not_exchange_the_subject() => Assert.False(_exchanged);

    [Fact]
    public void should_answer_with_the_failure_status() => Assert.Equal(HttpStatusCode.Forbidden, _callback!.StatusCode);
}
