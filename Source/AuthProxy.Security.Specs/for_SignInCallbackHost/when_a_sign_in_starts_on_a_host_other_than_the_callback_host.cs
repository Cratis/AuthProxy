// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.WebUtilities;

namespace Cratis.AuthProxy.Security.for_SignInCallbackHost;

/// <summary>
/// OWASP A07 — Identification and Authentication Failures. With a fixed callback host, the identity provider sees
/// exactly one callback address however many hosts the proxy serves, the handshake's own cookies exist only on that
/// host, and the person lands back on the page they asked for, signed in.
/// </summary>
/// <param name="harness">The running proxy, with one host fixed as the callback host.</param>
[Collection(FixedCallbackHostSpecCollection.Name)]
public class when_a_sign_in_starts_on_a_host_other_than_the_callback_host(FixedCallbackHostHarness harness) : IAsyncLifetime
{
    ProviderBrowser.Handshake? _handshake;
    HttpResponseMessage? _servedOnTheOriginalHost;

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        _handshake = await ProviderBrowser.SignIn(client, SessionCookieHarness.ChronicleHost, "/events?stream=7");

        _servedOnTheOriginalHost = await client.SendAsync(
            SessionCookieHarness.Request(SessionCookieHarness.ChronicleHost, "/api/events", [.. _handshake.Session]));
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact]
    public void should_send_the_browser_to_the_callback_host_before_anything_else() =>
        Assert.Equal(FixedCallbackHostHarness.CallbackHostName, _handshake!.Bounce!.Headers.Location!.Authority);

    [Fact]
    public void should_not_start_a_handshake_on_the_original_host() =>
        Assert.Empty(SessionCookieHarness.SetCookies(_handshake!.Bounce!));

    [Fact]
    public void should_run_the_handshake_on_the_callback_host() =>
        Assert.Equal(FixedCallbackHostHarness.CallbackHostName, _handshake!.ChallengeHost);

    [Fact]
    public void should_register_one_callback_address_with_the_identity_provider()
    {
        var redirectUri = QueryHelpers.ParseQuery(_handshake!.Challenge.Headers.Location!.Query)["redirect_uri"].ToString();
        Assert.Equal($"http://{FixedCallbackHostHarness.CallbackHostName}/signin-{SessionCookieHarness.ProviderScheme}", redirectUri);
    }

    [Fact]
    public void should_complete_the_handshake() =>
        Assert.Equal(HttpStatusCode.Found, _handshake!.Callback!.StatusCode);

    [Fact]
    public void should_send_the_person_back_to_the_page_they_asked_for_on_the_host_they_started_on() =>
        Assert.Equal($"http://{SessionCookieHarness.ChronicleHost}/events?stream=7", _handshake!.Callback!.Headers.Location!.ToString());

    [Fact]
    public void should_issue_a_session_valid_for_the_whole_domain() =>
        Assert.Contains(SessionCookieHarness.SetCookies(_handshake!.Callback!), _ => SessionCookieHarness.IsSettingOf(_, harness.CookieName) && SessionCookieHarness.HasDomain(_));

    [Fact]
    public void should_honor_that_session_on_the_original_host() =>
        Assert.True(_servedOnTheOriginalHost!.IsSuccessStatusCode);
}
