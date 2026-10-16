// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_SessionCookieDomain;

/// <summary>
/// OWASP A07 — Identification and Authentication Failures. Signing out on one host must end the session on every
/// host that shares it. A deletion written for the request host alone would leave the domain cookie alive, and the
/// caller signed in everywhere else.
/// </summary>
/// <param name="harness">The running proxy and its three origins.</param>
[Collection(SessionCookieSpecCollection.Name)]
public class when_a_session_is_ended_on_another_host(SessionCookieHarness harness) : IAsyncLifetime
{
    HttpResponseMessage? _logout;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        var session = SessionCookieHarness.SessionFrom(await harness.SignIn(client, SessionCookieHarness.ConsoleHost));

        _logout = await client.SendAsync(SessionCookieHarness.Request(SessionCookieHarness.OperationsHost, WellKnownPaths.Logout, session));
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void should_redirect_after_logging_out() =>
        Assert.Equal(HttpStatusCode.Found, _logout!.StatusCode);

    [Fact]
    public void should_delete_the_session_cookie_for_the_whole_domain() =>
        Assert.Contains(
            SessionCookieHarness.SetCookies(_logout!),
            _ => SessionCookieHarness.IsDeletionOf(_, harness.CookieName) && _.Contains($"domain={SessionCookieHarness.Domain}", StringComparison.OrdinalIgnoreCase));

    [Fact]
    public void should_also_delete_a_host_only_copy_left_by_an_earlier_deployment() =>
        Assert.Contains(
            SessionCookieHarness.SetCookies(_logout!),
            _ => SessionCookieHarness.IsDeletionOf(_, harness.CookieName) && !SessionCookieHarness.HasDomain(_));
}
