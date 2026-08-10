// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_TrustedProxies;

/// <summary>
/// The two forwarded headers AuthProxy does not consume are proven not to be consumed, from the peer best
/// placed to get away with it.
/// <para>
/// The host is the second half of the proxy's own public origin — the half a spoofed scheme cannot reach on
/// its own — so a deployment that started honoring it would let a caller name the origin the OIDC
/// <c>post_logout_redirect_uri</c> points at and the origin the post-logout allow-list admits. The prefix
/// moves every path the proxy matches on, which would silently reclassify a protected path as an anonymous
/// one. Neither is a header anyone would notice becoming trusted, which is why it is asserted rather than
/// assumed.
/// </para>
/// </summary>
/// <param name="harness">The running proxy, its origin, and the record of what each request was normalized to.</param>
[Collection(TrustedProxySpecCollection.Name)]
public class when_a_host_or_prefix_is_forwarded(TrustedProxyHarness harness) : IAsyncLifetime
{
    ObservedRequest? _observed;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();

        var request = TrustedProxyHarness.From(TrustedProxyHarness.TrustedPeer, TrustedProxyHarness.AnonymousPath);
        request.Headers.TryAddWithoutValidation("X-Forwarded-Host", "evil.example.com");
        request.Headers.TryAddWithoutValidation("X-Forwarded-Prefix", "/admin");

        await client.SendAsync(request);

        _observed = harness.Observations.Last;
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_have_observed_the_request() => Assert.NotNull(_observed);

    [Fact]
    public void should_keep_the_host_the_request_arrived_at() =>
        Assert.Equal("localhost", _observed!.Host);

    [Fact]
    public void should_not_be_moved_under_a_forwarded_prefix() =>
        Assert.Equal(string.Empty, _observed!.PathBase);
}
