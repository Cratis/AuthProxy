// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_CredentialLinkCallback;

/// <summary>
/// The control: a callback carrying the flow's own state, correlation cookie and session completes the link once, and a replay of the same callback does not.
/// </summary>
/// <param name="harness">The running proxy.</param>
[Collection(SessionCookieSpecCollection.Name)]
public class when_the_provider_answers_a_confirmed_link(SessionCookieHarness harness) : IAsyncLifetime
{
    HttpResponseMessage? _callback;
    int _exchangesAfterTheCallback;
    HttpResponseMessage? _replay;
    int _exchangesAfterTheReplay;

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        var browser = new CredentialLinkBrowser(harness);
        var session = await browser.SignIn(client);
        var (state, handshake) = await browser.Start(client, session);

        harness.ClearOrigins();
        _callback = await browser.Callback(client, state, [.. session, .. handshake]);
        _exchangesAfterTheCallback = Count();

        // The browser dropped the correlation cookie when the callback completed, so the replay carries the session only.
        _replay = await browser.Callback(client, state, session);
        _exchangesAfterTheReplay = Count();
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact]
    public void should_exchange_the_subject_once() => Assert.Equal(1, _exchangesAfterTheCallback);

    [Fact]
    public void should_redirect_to_the_completion_page() =>
        Assert.Equal(WellKnownPaths.LinkComplete, _callback!.Headers.Location?.ToString());

    [Fact]
    public void should_not_exchange_again_for_a_replayed_callback() => Assert.Equal(_exchangesAfterTheCallback, _exchangesAfterTheReplay);

    [Fact]
    public void should_not_complete_a_replayed_callback() => Assert.Null(_replay!.Headers.Location);

    int Count() => harness.ConsoleOrigin.Received.Count(_ => string.Equals(_.Path, SessionCookieHarness.LinkExchangePath, StringComparison.Ordinal));
}
