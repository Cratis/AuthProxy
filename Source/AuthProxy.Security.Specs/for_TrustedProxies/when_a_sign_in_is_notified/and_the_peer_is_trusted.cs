// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_TrustedProxies.when_a_sign_in_is_notified;

/// <summary>
/// A sign-in that genuinely came through the deployment's own CDN records where the person was, which is the
/// whole reason the geo headers are read at all.
/// <para>
/// Without this the refusing spec next to it would be satisfied by a resolver that had simply stopped
/// working: an empty location and the socket address are also what a broken implementation reports. Here the
/// same headers, from a peer inside the declared range, produce a real address and a real place.
/// </para>
/// </summary>
/// <param name="harness">The running proxy, its origin, and the record of what each request was normalized to.</param>
[Collection(TrustedProxySpecCollection.Name)]
public class and_the_peer_is_trusted(TrustedProxyHarness harness) : IAsyncLifetime
{
    string? _notification;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();

        harness.Origin.Clear();

        var request = TrustedProxyHarness.SigningInFrom(TrustedProxyHarness.TrustedPeer, TrustedProxyHarness.AnonymousPath);
        request.Headers.TryAddWithoutValidation("X-Forwarded-For", $"192.0.2.5, {TrustedProxyHarness.SecondTrustedPeer}");
        request.Headers.TryAddWithoutValidation("X-Geo-City", "Oslo");
        request.Headers.TryAddWithoutValidation("X-Geo-Country", "NO");

        await client.SendAsync(request);

        _notification = harness.Origin.LastSignInNotification();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_have_notified_the_application() => Assert.NotNull(_notification);

    [Fact]
    public void should_report_the_client_the_ingress_declared() =>
        Assert.Contains("\"ipAddress\":\"192.0.2.5\"", _notification, StringComparison.Ordinal);

    [Fact]
    public void should_report_the_location_the_ingress_declared() =>
        Assert.Contains("\"location\":\"Oslo, NO\"", _notification, StringComparison.Ordinal);
}
