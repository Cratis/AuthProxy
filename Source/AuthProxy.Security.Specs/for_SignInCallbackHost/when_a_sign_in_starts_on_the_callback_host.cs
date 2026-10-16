// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_SignInCallbackHost;

/// <summary>
/// OWASP A07 — Identification and Authentication Failures. The callback host is where the handshake runs, so a
/// sign-in that starts there must not be sent anywhere first.
/// </summary>
/// <param name="harness">The running proxy, with one host fixed as the callback host.</param>
[Collection(FixedCallbackHostSpecCollection.Name)]
public class when_a_sign_in_starts_on_the_callback_host(FixedCallbackHostHarness harness) : IAsyncLifetime
{
    ProviderBrowser.Handshake? _handshake;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        _handshake = await ProviderBrowser.SignIn(client, FixedCallbackHostHarness.CallbackHostName, "/welcome");
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void should_not_bounce() => Assert.Null(_handshake!.Bounce);

    [Fact]
    public void should_challenge_on_the_callback_host() =>
        Assert.Equal(FixedCallbackHostHarness.CallbackHostName, _handshake!.ChallengeHost);

    [Fact]
    public void should_complete_the_handshake() =>
        Assert.Equal(HttpStatusCode.Found, _handshake!.Callback!.StatusCode);

    [Fact]
    public void should_return_to_the_relative_destination() =>
        Assert.Equal("/welcome", _handshake!.Callback!.Headers.Location!.ToString());
}
