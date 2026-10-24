// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_SessionCookieDomain;

/// <summary>
/// OWASP A07 — Identification and Authentication Failures. A browser that signed in before the cookie moved to the
/// parent domain holds a host-only copy next to the shared one. The stale copy has to be removed, and removing it
/// must never remove the shared cookie, or every move to a shared domain would sign everyone out in a loop.
/// </summary>
/// <param name="harness">The running proxy and its three origins.</param>
[Collection(SessionCookieSpecCollection.Name)]
public class when_a_browser_holds_a_host_only_copy_of_the_session(SessionCookieHarness harness) : IAsyncLifetime
{
    HttpResponseMessage? _requestWithBothCopies;
    IReadOnlyList<string> _requestSetCookies = [];
    IReadOnlyList<string> _signInSetCookies = [];

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        var shared = SessionCookieHarness.SessionFrom(await harness.SignIn(client, SessionCookieHarness.ConsoleHost)).Single();

        // The copy an earlier deployment issued is a real session of its own, from the same keys.
        var stale = SessionCookieHarness.SessionFrom(await harness.SignIn(client, SessionCookieHarness.ConsoleHost)).Single();

        _requestWithBothCopies = await client.SendAsync(SessionCookieHarness.Request(SessionCookieHarness.ChronicleHost, "/api/events", shared, stale));
        _requestSetCookies = SessionCookieHarness.SetCookies(_requestWithBothCopies);

        _signInSetCookies = SessionCookieHarness.SetCookies(await harness.SignIn(client, SessionCookieHarness.ConsoleHost, withOperationsClaim: false, stale));
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact]
    public void should_delete_the_host_only_copy_when_the_cookie_arrives_twice() =>
        Assert.Contains(_requestSetCookies, _ => SessionCookieHarness.IsDeletionOf(_, harness.CookieName) && !SessionCookieHarness.HasDomain(_));

    [Fact]
    public void should_never_delete_the_shared_cookie_while_cleaning_up() =>
        Assert.DoesNotContain(_requestSetCookies, _ => SessionCookieHarness.IsDeletionOf(_, harness.CookieName) && SessionCookieHarness.HasDomain(_));

    [Fact]
    public void should_still_serve_the_request() =>
        Assert.True(_requestWithBothCopies!.IsSuccessStatusCode);

    [Fact]
    public void should_delete_the_host_only_copy_when_a_new_session_is_issued() =>
        Assert.Contains(_signInSetCookies, _ => SessionCookieHarness.IsDeletionOf(_, harness.CookieName) && !SessionCookieHarness.HasDomain(_));

    [Fact]
    public void should_issue_the_new_session_for_the_whole_domain() =>
        Assert.Contains(_signInSetCookies, _ => SessionCookieHarness.IsSettingOf(_, harness.CookieName) && SessionCookieHarness.HasDomain(_));

    [Fact]
    public void should_delete_the_host_only_copy_after_the_new_session_is_written() =>
        Assert.True(
            IndexOf(_signInSetCookies, _ => SessionCookieHarness.IsSettingOf(_, harness.CookieName)) < IndexOf(_signInSetCookies, _ => SessionCookieHarness.IsDeletionOf(_, harness.CookieName) && !SessionCookieHarness.HasDomain(_)),
            "A deletion that came first could be applied after the new cookie and take it with it.");

    static int IndexOf(IReadOnlyList<string> values, Func<string, bool> predicate)
    {
        for (var i = 0; i < values.Count; i++)
        {
            if (predicate(values[i]))
            {
                return i;
            }
        }

        return -1;
    }
}
