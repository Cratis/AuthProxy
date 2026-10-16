// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_SessionCookieDomain;

/// <summary>
/// OWASP A05 — Security Misconfiguration. A deployment that never asked for a shared session must keep issuing,
/// honoring and deleting a cookie that belongs to one host alone: the same name, no <c language="text">Domain</c>, one header per
/// change, and nothing extra deleted.
/// </summary>
/// <param name="harness">The running proxy, with no session cookie domain configured.</param>
[Collection(HostOnlySessionCookieSpecCollection.Name)]
public class when_no_session_cookie_domain_is_configured(HostOnlySessionCookieHarness harness) : IAsyncLifetime
{
    IReadOnlyList<string> _signIn = [];
    IReadOnlyList<string> _logout = [];
    IReadOnlyList<string> _requestWithTheCookieTwice = [];
    HttpResponseMessage? _usedOnAnotherHost;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        var signedIn = await harness.SignIn(client, SessionCookieHarness.ConsoleHost);
        _signIn = SessionCookieHarness.SetCookies(signedIn);
        var session = SessionCookieHarness.SessionFrom(signedIn);

        _usedOnAnotherHost = await client.SendAsync(SessionCookieHarness.Request(SessionCookieHarness.ChronicleHost, "/api/events", session));
        _requestWithTheCookieTwice = SessionCookieHarness.SetCookies(
            await client.SendAsync(SessionCookieHarness.Request(SessionCookieHarness.ChronicleHost, "/api/events", [.. session, .. session])));
        _logout = SessionCookieHarness.SetCookies(await client.SendAsync(SessionCookieHarness.Request(SessionCookieHarness.ChronicleHost, WellKnownPaths.Logout, session)));
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void should_keep_the_default_cookie_name() =>
        Assert.Equal(".Cratis.AuthProxy.Auth.v2", harness.CookieName);

    [Fact]
    public void should_issue_the_session_cookie_under_the_default_name() =>
        Assert.Contains(_signIn, _ => SessionCookieHarness.IsSettingOf(_, ".Cratis.AuthProxy.Auth.v2"));

    [Fact]
    public void should_issue_the_session_cookie_without_a_domain() =>
        Assert.DoesNotContain(_signIn, SessionCookieHarness.HasDomain);

    [Fact]
    public void should_write_exactly_one_header_for_the_session_cookie() =>
        Assert.Single(_signIn, _ => _.StartsWith(".Cratis.AuthProxy.Auth.v2", StringComparison.Ordinal));

    [Fact]
    public void should_still_honor_the_session_it_issued() =>
        Assert.NotEqual(HttpStatusCode.Unauthorized, _usedOnAnotherHost!.StatusCode);

    [Fact]
    public void should_not_delete_anything_because_a_cookie_was_sent_twice() =>
        Assert.DoesNotContain(_requestWithTheCookieTwice, _ => SessionCookieHarness.IsDeletionOf(_, harness.CookieName));

    [Fact]
    public void should_delete_the_session_cookie_on_logout_without_a_domain() =>
        Assert.Contains(_logout, _ => SessionCookieHarness.IsDeletionOf(_, harness.CookieName) && !SessionCookieHarness.HasDomain(_));

    [Fact]
    public void should_delete_the_session_cookie_exactly_once_on_logout() =>
        Assert.Single(_logout, _ => SessionCookieHarness.IsDeletionOf(_, harness.CookieName));
}
