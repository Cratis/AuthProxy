// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_SignInCallbackHost;

/// <summary>
/// OWASP A01 — Broken Access Control (unvalidated redirects). Signing out shares its allow-list with signing in, so a
/// fixed callback host that lets a person return to another declared host must not let a sign-out be sent anywhere
/// else. The hosts a service declares are trusted only because a callback host is configured.
/// </summary>
/// <param name="harness">The running proxy, with one host fixed as the callback host.</param>
[Collection(FixedCallbackHostSpecCollection.Name)]
public class when_the_sign_out_target_cannot_be_trusted(FixedCallbackHostHarness harness) : IAsyncLifetime
{
    readonly Dictionary<string, string> _destinations = [];

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        var session = SessionCookieHarness.SessionFrom(await harness.SignIn(client, SessionCookieHarness.ConsoleHost));

        foreach (var target in new[]
        {
            "http://operations.example.test/goodbye",
            "http://undeclared.example.test/phish",
            "http://evil.test/phish",
            "http://console.example.test@evil.test/x",
            "//evil.test/phish",
            "javascript:alert(1)",
        })
        {
            var response = await client.SendAsync(SessionCookieHarness.Request(
                FixedCallbackHostHarness.CallbackHostName,
                $"{WellKnownPaths.Logout}?redirect={Uri.EscapeDataString(target)}",
                [.. session]));
            _destinations[target] = response.Headers.Location!.ToString();
        }
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact]
    public void should_return_to_a_declared_host() =>
        Assert.Equal("http://operations.example.test/goodbye", _destinations["http://operations.example.test/goodbye"]);

    [Fact]
    public void should_send_a_host_no_service_declares_to_the_root() =>
        Assert.Equal("/", _destinations["http://undeclared.example.test/phish"]);

    [Fact]
    public void should_send_a_foreign_host_to_the_root() =>
        Assert.Equal("/", _destinations["http://evil.test/phish"]);

    [Fact]
    public void should_send_user_information_that_hides_a_foreign_host_to_the_root() =>
        Assert.Equal("/", _destinations["http://console.example.test@evil.test/x"]);

    [Fact]
    public void should_send_a_protocol_relative_address_to_the_root() =>
        Assert.Equal("/", _destinations["//evil.test/phish"]);

    [Fact]
    public void should_send_a_script_address_to_the_root() =>
        Assert.Equal("/", _destinations["javascript:alert(1)"]);
}
