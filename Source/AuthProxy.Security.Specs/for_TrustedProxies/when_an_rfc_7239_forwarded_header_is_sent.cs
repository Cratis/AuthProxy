// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_TrustedProxies;

/// <summary>
/// The standardized <c>Forwarded</c> header changes nothing, even from a peer the deployment trusts.
/// <para>
/// It is the header a reader of RFC 7239 would reach for, and AuthProxy consumes only the <c>X-Forwarded-*</c>
/// family — so a value here is inert. That is worth pinning from the trusted side rather than the untrusted
/// one: from an outsider it would be refused anyway, and the claim being made is the stronger one that no
/// amount of trust makes this header mean anything. The sign-in notification is asserted alongside, because a
/// second parser appearing anywhere downstream is exactly how a header the boundary ignores becomes a value
/// the audit record believes.
/// </para>
/// </summary>
/// <param name="harness">The running proxy, its origin, and the record of what each request was normalized to.</param>
[Collection(TrustedProxySpecCollection.Name)]
public class when_an_rfc_7239_forwarded_header_is_sent(TrustedProxyHarness harness) : IAsyncLifetime
{
    ObservedRequest? _observed;
    string? _notification;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();

        harness.Origin.Clear();

        var request = TrustedProxyHarness.SigningInFrom(TrustedProxyHarness.TrustedPeer, TrustedProxyHarness.AnonymousPath);
        request.Headers.TryAddWithoutValidation("Forwarded", "for=192.0.2.60;proto=https;host=evil.example.com");

        await client.SendAsync(request);

        _observed = harness.Observations.Last;
        _notification = harness.Origin.LastSignInNotification();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_have_observed_the_request() => Assert.NotNull(_observed);
    [Fact] public void should_have_notified_the_application() => Assert.NotNull(_notification);

    [Fact]
    public void should_leave_the_address_alone() =>
        Assert.Equal(TrustedProxyHarness.TrustedPeer, _observed!.RemoteIpAddress);

    [Fact]
    public void should_leave_the_scheme_alone() =>
        Assert.Equal("http", _observed!.Scheme);

    [Fact]
    public void should_leave_the_host_alone() =>
        Assert.DoesNotContain("evil.example.com", _observed!.Host, StringComparison.OrdinalIgnoreCase);

    [Fact]
    public void should_leave_the_notified_address_alone() =>
        Assert.Contains($"\"ipAddress\":\"{TrustedProxyHarness.TrustedPeer}\"", _notification, StringComparison.Ordinal);

    [Fact]
    public void should_not_notify_the_address_the_header_named() =>
        Assert.DoesNotContain("192.0.2.60", _notification, StringComparison.Ordinal);
}
