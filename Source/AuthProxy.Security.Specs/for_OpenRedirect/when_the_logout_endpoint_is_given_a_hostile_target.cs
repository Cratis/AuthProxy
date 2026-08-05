// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_OpenRedirect;

/// <summary>
/// OWASP A01 — an authentication proxy must never redirect a caller off-site on request.
/// <para>
/// An open redirect here is worth more to an attacker than almost anywhere else: the victim is handed a
/// link on the real domain, watches a real sign-out complete, and only then lands on the attacker's page —
/// so every signal a careful person is taught to check says the page is genuine. That is why the target is
/// validated against an allow-list rather than merely being made to "look relative".
/// </para>
/// <para>
/// A single leading slash is not what makes a URL same-site, and the payloads below are the ways that
/// assumption fails. <c>//evil.test</c> is protocol-relative. <c>/\evil.test</c> is the same URL to every
/// major browser, which normalize a backslash to a slash in the authority position. A slash followed by a
/// tab, carriage return or newline is also the same URL, because browsers strip those characters before
/// parsing — so the string the server checked and the URL the browser fetched are different strings. Every
/// one of them must come back as the application root.
/// </para>
/// </summary>
/// <param name="harness">The running proxy and its origin.</param>
[Collection(SecuritySpecCollection.Name)]
public class when_the_logout_endpoint_is_given_a_hostile_target(SecurityHarness harness) : IAsyncLifetime
{
    static readonly string[] _hostileTargets =
    [
        "//evil.test",
        "//evil.test/phish",
        "///evil.test",
        "/\\evil.test",
        "/\\/evil.test",
        "/\\\\evil.test",
        "\\\\evil.test",
        "https://evil.test",
        "http://evil.test/phish",
        "//evil.test:8080/phish",
        "/\tevil.test",
        "/\t//evil.test",
        "/\r\n//evil.test",
        "/ /evil.test",
        "javascript:alert(1)",
        "//user:pass@evil.test",
    ];

    static readonly string[] _safeTargets =
    [
        "/",
        "/dashboard",
        "/dashboard/reports",
        "/dashboard?tab=overview",
        "/a-b_c~d.e",
    ];

    readonly Dictionary<string, string> _locations = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets the redirect targets that must never be honored, in the raw form a caller would put in the
    /// query string.
    /// </summary>
    public static TheoryData<string> HostileTargets => new(_hostileTargets);

    /// <summary>
    /// Gets the targets that are genuinely same-site and must keep working, so the guard is not simply
    /// refusing everything.
    /// </summary>
    public static TheoryData<string> SafeTargets => new(_safeTargets);

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();

        foreach (var target in _hostileTargets.Concat(_safeTargets))
        {
            var response = await client.SendAsync(SecurityHarness.Authenticated(
                HttpMethod.Get,
                $"{WellKnownPaths.Logout}?redirect={Uri.EscapeDataString(target)}"));

            _locations[target] = response.Headers.Location?.OriginalString ?? string.Empty;
        }
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Theory]
    [MemberData(nameof(HostileTargets))]
    public void should_send_a_hostile_target_to_the_application_root(string target) =>
        Assert.Equal(RelativeRedirect.ApplicationRoot, _locations[target]);

    [Theory]
    [MemberData(nameof(SafeTargets))]
    public void should_honor_a_same_site_target(string target) =>
        Assert.Equal(target, _locations[target]);

    [Theory]
    [MemberData(nameof(HostileTargets))]
    public void should_never_name_the_attacker_host_in_the_location(string target) =>
        Assert.DoesNotContain("evil.test", _locations[target], StringComparison.OrdinalIgnoreCase);
}
