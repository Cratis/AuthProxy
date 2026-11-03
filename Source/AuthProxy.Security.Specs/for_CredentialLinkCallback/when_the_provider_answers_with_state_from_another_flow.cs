// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_CredentialLinkCallback;

/// <summary>
/// State protected for another browser's flow must not complete this browser's link.
/// </summary>
/// <param name="harness">The running proxy.</param>
[Collection(SessionCookieSpecCollection.Name)]
public class when_the_provider_answers_with_state_from_another_flow(SessionCookieHarness harness) : IAsyncLifetime
{
    HttpResponseMessage? _callback;
    bool _exchanged;

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        var browser = new CredentialLinkBrowser(harness);
        var session = await browser.SignIn(client);
        var (_, handshake) = await browser.Start(client, session);
        var (otherState, _) = await browser.Start(client, await browser.SignIn(client));

        harness.ClearOrigins();
        _callback = await browser.Callback(client, otherState, [.. session, .. handshake]);
        _exchanged = harness.ConsoleOrigin.ReceivedAnythingFor(SessionCookieHarness.LinkExchangePath);
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact]
    public void should_not_exchange_the_subject() => Assert.False(_exchanged);

    [Fact]
    public void should_not_complete_the_link() => Assert.NotEqual(WellKnownPaths.LinkComplete, _callback!.Headers.Location?.ToString());
}
