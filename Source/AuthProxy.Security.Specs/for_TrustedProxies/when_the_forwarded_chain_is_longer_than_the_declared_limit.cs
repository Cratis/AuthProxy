// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_TrustedProxies;

/// <summary>
/// A chain longer than the deployment has hops is followed exactly as far as it declared and no further.
/// <para>
/// The surplus is where a caller behind a correctly configured ingress puts whatever it wants the audit
/// record to say: it prepends an entry, the real ingress appends its own, and a proxy that walked the whole
/// chain would arrive at the attacker's value having checked every hop along the way. The limit is what stops
/// it, which makes it a security setting rather than a tuning knob.
/// </para>
/// </summary>
/// <param name="harness">The running proxy, its origin, and the record of what each request was normalized to.</param>
[Collection(TrustedProxySpecCollection.Name)]
public class when_the_forwarded_chain_is_longer_than_the_declared_limit(TrustedProxyHarness harness) : IAsyncLifetime
{
    const string Surplus = "192.0.2.9";

    ObservedRequest? _observed;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();

        var request = TrustedProxyHarness.From(TrustedProxyHarness.TrustedPeer, TrustedProxyHarness.AnonymousPath);
        request.Headers.TryAddWithoutValidation(
            "X-Forwarded-For",
            $"{Surplus}, {TrustedProxyHarness.ThirdTrustedPeer}, {TrustedProxyHarness.SecondTrustedPeer}");

        await client.SendAsync(request);

        _observed = harness.Observations.Last;
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_have_observed_the_request() => Assert.NotNull(_observed);

    [Fact]
    public void should_consume_exactly_the_declared_number_of_hops() =>
        Assert.Equal(TrustedProxyHarness.ThirdTrustedPeer, _observed!.RemoteIpAddress);

    [Fact]
    public void should_never_reach_the_surplus_entry() =>
        Assert.NotEqual(Surplus, _observed!.RemoteIpAddress);

    [Fact]
    public void should_leave_the_surplus_where_it_was() =>
        Assert.Equal(Surplus, _observed!.RemainingForwardedFor);
}
