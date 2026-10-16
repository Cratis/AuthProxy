// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.WebUtilities;

namespace Cratis.AuthProxy.Security.for_SignInCallbackHost;

/// <summary>
/// OWASP A05 — Security Misconfiguration. A deployment with a shared session cookie but no callback host must go on
/// running its handshake on each host and reducing every return URL to a path, exactly as it did before the setting
/// existed: the callback host is what opts into absolute return URLs, and nothing else may.
/// </summary>
/// <param name="harness">The running proxy, with a cookie domain and no callback host.</param>
[Collection(SessionCookieSpecCollection.Name)]
public class when_a_callback_host_is_not_configured(SessionCookieHarness harness) : IAsyncLifetime
{
    ProviderBrowser.Handshake? _handshake;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        _handshake = await ProviderBrowser.SignIn(client, SessionCookieHarness.ChronicleHost, "http://operations.example.test/users?page=2");
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void should_not_bounce() => Assert.Null(_handshake!.Bounce);

    [Fact]
    public void should_run_the_handshake_on_the_host_it_started_on() =>
        Assert.Equal(SessionCookieHarness.ChronicleHost, _handshake!.ChallengeHost);

    [Fact]
    public void should_register_the_callback_of_that_host_with_the_identity_provider()
    {
        var redirectUri = QueryHelpers.ParseQuery(_handshake!.Challenge.Headers.Location!.Query)["redirect_uri"].ToString();
        Assert.Equal($"http://{SessionCookieHarness.ChronicleHost}/signin-{SessionCookieHarness.ProviderScheme}", redirectUri);
    }

    [Fact]
    public void should_still_reduce_an_absolute_return_url_to_its_path_and_query() =>
        Assert.Equal("/users?page=2", _handshake!.Callback!.Headers.Location!.ToString());
}
