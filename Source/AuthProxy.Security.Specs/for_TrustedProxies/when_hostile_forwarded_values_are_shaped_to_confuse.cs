// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_TrustedProxies;

/// <summary>
/// OWASP A03 — Injection. Sending every confusing shape of forwarded header at once leaves the request in
/// exactly the state sending none would have.
/// <para>
/// Parsers are where boundaries are usually defeated rather than at the check itself: a duplicated header
/// under a different case, an empty entry inside a comma list, padding around a value, or two headers that
/// contradict each other are all attempts to find the code path that reads a value the check never saw. The
/// assertion is deliberately an equality against the no-headers case rather than a list of specific
/// rejections, because that is the only form that also covers the shapes nobody thought of.
/// </para>
/// </summary>
/// <param name="harness">The running proxy, its origin, and the record of what each request was normalized to.</param>
[Collection(TrustedProxySpecCollection.Name)]
public class when_hostile_forwarded_values_are_shaped_to_confuse(TrustedProxyHarness harness) : IAsyncLifetime
{
    ObservedRequest? _withHostileValues;
    ObservedRequest? _withNothing;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();

        var hostile = TrustedProxyHarness.From(TrustedProxyHarness.UntrustedPeer, TrustedProxyHarness.AnonymousPath);
        hostile.Headers.TryAddWithoutValidation("X-Forwarded-For", " 203.0.113.7 ,10.0.0.1 , , 192.0.2.1 ");
        hostile.Headers.TryAddWithoutValidation("x-forwarded-for", "172.16.0.1");
        hostile.Headers.TryAddWithoutValidation("X-Forwarded-Proto", "HTTPS");
        hostile.Headers.TryAddWithoutValidation("x-forwarded-proto", "http");
        hostile.Headers.TryAddWithoutValidation("X-Forwarded-Host", "evil.example.com");
        hostile.Headers.TryAddWithoutValidation("X-Forwarded-Prefix", "/admin");
        hostile.Headers.TryAddWithoutValidation("Forwarded", "for=192.0.2.60;proto=https;host=evil.example.com");

        await client.SendAsync(hostile);
        _withHostileValues = harness.Observations.Last;

        await client.SendAsync(TrustedProxyHarness.From(TrustedProxyHarness.UntrustedPeer, TrustedProxyHarness.AnonymousPath));
        _withNothing = harness.Observations.Last;
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_have_observed_both_requests() => Assert.NotNull(_withHostileValues);

    [Fact]
    public void should_normalize_the_address_identically() =>
        Assert.Equal(_withNothing!.RemoteIpAddress, _withHostileValues!.RemoteIpAddress);

    [Fact]
    public void should_normalize_the_scheme_identically() =>
        Assert.Equal(_withNothing!.Scheme, _withHostileValues!.Scheme);

    [Fact]
    public void should_normalize_the_host_identically() =>
        Assert.Equal(_withNothing!.Host, _withHostileValues!.Host);

    [Fact]
    public void should_normalize_the_path_base_identically() =>
        Assert.Equal(_withNothing!.PathBase, _withHostileValues!.PathBase);

    [Fact]
    public void should_settle_on_the_address_the_connection_came_from() =>
        Assert.Equal(TrustedProxyHarness.UntrustedPeer, _withHostileValues!.RemoteIpAddress);

    [Fact]
    public void should_settle_on_the_real_transport_scheme() =>
        Assert.Equal("http", _withHostileValues!.Scheme);
}
