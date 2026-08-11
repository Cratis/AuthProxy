// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_TrustedProxies.when_a_sign_in_is_notified;

/// <summary>
/// OWASP A09 — Security Logging and Monitoring Failures. The record the application keeps of who signed in
/// from where must not be writable by the person signing in.
/// <para>
/// This is the payload an application shows a user as "a new sign-in from Oslo, 203.0.113.7" and acts on when
/// it looks unfamiliar. An untrusted caller sending a forwarded address and a set of geo headers is claiming
/// both halves of that sentence outright, and a record that can be dictated by its subject is worse than no
/// record: it is a record everything downstream still trusts.
/// </para>
/// </summary>
/// <param name="harness">The running proxy, its origin, and the record of what each request was normalized to.</param>
[Collection(TrustedProxySpecCollection.Name)]
public class and_the_peer_is_not_trusted(TrustedProxyHarness harness) : IAsyncLifetime
{
    ObservedRequest? _observed;
    string? _notification;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();

        harness.Origin.Clear();

        var request = TrustedProxyHarness.SigningInFrom(TrustedProxyHarness.UntrustedPeer, TrustedProxyHarness.AnonymousPath);
        request.Headers.TryAddWithoutValidation("X-Forwarded-For", "203.0.113.7, 10.0.0.1");
        request.Headers.TryAddWithoutValidation("X-Forwarded-Proto", "https");
        request.Headers.TryAddWithoutValidation("X-Geo-City", "Oslo");
        request.Headers.TryAddWithoutValidation("X-Geo-Country", "NO");
        request.Headers.TryAddWithoutValidation("CF-IPCountry", "NO");

        await client.SendAsync(request);

        _observed = harness.Observations.Last;
        _notification = harness.Origin.LastSignInNotification();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_have_notified_the_application() => Assert.NotNull(_notification);

    [Fact]
    public void should_report_the_address_the_connection_came_from() =>
        Assert.Contains($"\"ipAddress\":\"{TrustedProxyHarness.UntrustedPeer}\"", _notification, StringComparison.Ordinal);

    [Fact]
    public void should_not_report_the_leftmost_forwarded_address() =>
        Assert.DoesNotContain("203.0.113.7", _notification, StringComparison.Ordinal);

    [Fact]
    public void should_not_report_the_rightmost_forwarded_address() =>
        Assert.DoesNotContain("10.0.0.1", _notification, StringComparison.Ordinal);

    [Fact]
    public void should_report_no_location_at_all() =>
        Assert.Contains("\"location\":\"\"", _notification, StringComparison.Ordinal);

    [Fact]
    public void should_not_report_a_place_the_caller_named() =>
        Assert.DoesNotContain("Oslo", _notification, StringComparison.Ordinal);

    [Fact]
    public void should_have_left_the_scheme_alone_as_well() =>
        Assert.Equal("http", _observed!.Scheme);
}
