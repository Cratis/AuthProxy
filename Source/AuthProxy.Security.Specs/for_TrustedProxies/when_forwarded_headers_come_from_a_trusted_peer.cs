// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_TrustedProxies;

/// <summary>
/// The deployment's own ingress is believed, for exactly as many hops as it declared.
/// <para>
/// This is the direction that makes the refusing direction mean something. A boundary that refused everyone
/// would pass every "an attacker cannot" spec while breaking every real deployment, so the same chain that is
/// ignored from an outsider is followed here, two hops deep, and both the address and the scheme change.
/// </para>
/// <para>
/// Two hops rather than one on purpose: the framework's own default is one, so a single hop would pass
/// whether or not the declared limit ever reached the middleware.
/// </para>
/// </summary>
/// <param name="harness">The running proxy, its origin, and the record of what each request was normalized to.</param>
[Collection(TrustedProxySpecCollection.Name)]
public class when_forwarded_headers_come_from_a_trusted_peer(TrustedProxyHarness harness) : IAsyncLifetime
{
    ObservedRequest? _observed;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();

        var request = TrustedProxyHarness.From(TrustedProxyHarness.TrustedPeer, TrustedProxyHarness.AnonymousPath);
        request.Headers.TryAddWithoutValidation("X-Forwarded-For", $"192.0.2.5, {TrustedProxyHarness.SecondTrustedPeer}");
        request.Headers.TryAddWithoutValidation("X-Forwarded-Proto", "https");

        await client.SendAsync(request);

        _observed = harness.Observations.Last;
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_have_observed_the_request() => Assert.NotNull(_observed);

    [Fact]
    public void should_follow_the_chain_to_the_declared_client() =>
        Assert.Equal("192.0.2.5", _observed!.RemoteIpAddress);

    [Fact]
    public void should_take_the_forwarded_scheme() =>
        Assert.Equal("https", _observed!.Scheme);

    [Fact]
    public void should_consume_the_whole_chain_it_followed() =>
        Assert.Equal(string.Empty, _observed!.RemainingForwardedFor);
}
