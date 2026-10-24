// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_SignInCallbackHost;

/// <summary>
/// OWASP A01 — Broken Access Control (unvalidated redirects). A fixed callback host is what makes an absolute return
/// URL possible at all, and an absolute return URL after a completed sign-in is the most attractive open redirect the
/// proxy has: the person sees the real domain and a real login before it is honored. Only the origins of declared
/// hosts, inside the cookie domain, on the scheme the request arrived on, may survive; everything else must collapse
/// to a path on the proxy itself.
/// </summary>
/// <param name="harness">The running proxy, with one host fixed as the callback host.</param>
[Collection(FixedCallbackHostSpecCollection.Name)]
public class when_the_return_url_cannot_be_trusted(FixedCallbackHostHarness harness) : IAsyncLifetime
{
    static readonly string _punycodeLookAlike = new System.Globalization.IdnMapping().GetAscii("cönsole.example.test");

    readonly Dictionary<string, string> _destinations = [];

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();

        foreach (var returnUrl in new[]
        {
            "http://console.example.test/dashboard?tab=2#section",
            "http://operations.example.test/users",
            "http://undeclared.example.test/phish",
            "http://evil.test/phish",
            $"{SessionCookieHarness.OutsideTheDomainOrigin}/landing",
            "https://console.example.test/downgraded",
            "http://console.example.test:8081/x",
            "http://console.example.test@evil.test/x",
            "http://someone:secret@console.example.test/x",
            $"http://{_punycodeLookAlike}/x",
            "http://evilconsole.example.test/x",
            "//evil.test/phish",
            "/\\evil.test",
            "javascript:alert(1)",
            "ftp://console.example.test/x",
        })
        {
            var handshake = await ProviderBrowser.SignIn(client, FixedCallbackHostHarness.CallbackHostName, returnUrl);
            _destinations[returnUrl] = handshake.Callback!.Headers.Location!.ToString();
        }
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact]
    public void should_keep_an_absolute_address_on_a_declared_host() =>
        Assert.Equal("http://console.example.test/dashboard?tab=2", _destinations["http://console.example.test/dashboard?tab=2#section"]);

    [Fact]
    public void should_keep_an_absolute_address_on_another_declared_host() =>
        Assert.Equal("http://operations.example.test/users", _destinations["http://operations.example.test/users"]);

    [Fact]
    public void should_reduce_a_host_under_the_domain_that_no_service_declares() =>
        Assert.Equal("/phish", _destinations["http://undeclared.example.test/phish"]);

    [Fact]
    public void should_reduce_a_host_outside_the_domain() =>
        Assert.Equal("/phish", _destinations["http://evil.test/phish"]);

    [Fact]
    public void should_reduce_an_origin_a_sign_out_trusts_but_the_session_cookie_does_not_reach() =>
        Assert.Equal("/landing", _destinations[$"{SessionCookieHarness.OutsideTheDomainOrigin}/landing"]);

    [Fact]
    public void should_reduce_an_address_on_another_scheme_than_the_request_arrived_on() =>
        Assert.Equal("/downgraded", _destinations["https://console.example.test/downgraded"]);

    [Fact]
    public void should_reduce_a_port_the_host_does_not_declare() =>
        Assert.Equal("/x", _destinations["http://console.example.test:8081/x"]);

    [Fact]
    public void should_reduce_a_declared_host_used_as_user_information_for_another() =>
        Assert.Equal("/x", _destinations["http://console.example.test@evil.test/x"]);

    [Fact]
    public void should_reduce_an_address_that_carries_user_information() =>
        Assert.Equal("/x", _destinations["http://someone:secret@console.example.test/x"]);

    [Fact]
    public void should_reduce_a_punycode_look_alike_of_a_declared_host() =>
        Assert.Equal("/x", _destinations[$"http://{_punycodeLookAlike}/x"]);

    [Fact]
    public void should_reduce_a_host_that_only_ends_with_a_declared_host() =>
        Assert.Equal("/x", _destinations["http://evilconsole.example.test/x"]);

    [Fact]
    public void should_send_a_protocol_relative_address_to_the_root() =>
        Assert.Equal("/", _destinations["//evil.test/phish"]);

    [Fact]
    public void should_send_a_backslash_address_to_the_root() =>
        Assert.Equal("/", _destinations["/\\evil.test"]);

    [Fact]
    public void should_send_a_script_address_to_the_root() =>
        Assert.Equal("/", _destinations["javascript:alert(1)"]);

    [Fact]
    public void should_send_an_address_on_another_protocol_to_the_root() =>
        Assert.Equal("/", _destinations["ftp://console.example.test/x"]);
}
