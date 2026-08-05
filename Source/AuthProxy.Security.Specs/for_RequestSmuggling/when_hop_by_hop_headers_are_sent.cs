// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_RequestSmuggling;

/// <summary>
/// A proxy must end the client's connection and start a new one, not extend the client's connection to the
/// origin. Hop-by-hop headers are the difference.
/// <para>
/// <c>Connection</c>, <c>Keep-Alive</c>, <c>Proxy-Connection</c>, <c>Upgrade</c>, <c>TE</c> and
/// <c>Transfer-Encoding</c> describe a single hop — how these two endpoints agreed to frame and hold this
/// one connection. Relaying them makes the origin negotiate a connection with a client it is not connected
/// to. That is where request smuggling lives: an attacker who can get <c>Transfer-Encoding</c> past the
/// proxy makes the proxy and the origin disagree about where one request ends and the next begins, and
/// then owns the front of somebody else's request — every access-control decision the proxy just made gets
/// applied to a body the attacker wrote. <c>Upgrade</c> is the same failure in one step: an origin that
/// accepts a relayed upgrade leaves a raw tunnel behind the proxy that no later request ever passes through
/// it again.
/// </para>
/// <para>
/// None of this is visible from the client-facing response — a smuggled request looks like a perfectly
/// ordinary one until it lands on a different victim's connection. So the assertion is made against a real
/// origin that records what it actually received, on the declared anonymous path, which is the one route
/// an unauthenticated attacker can reach without any credential at all.
/// </para>
/// </summary>
/// <param name="harness">The running proxy and its origin.</param>
[Collection(SecuritySpecCollection.Name)]
public class when_hop_by_hop_headers_are_sent(SecurityHarness harness) : IAsyncLifetime
{
    ForwardedRequest? _forwarded;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();

        harness.Origin.Clear();
        await client.SendAsync(HopByHop(SecurityHarness.Anonymous(HttpMethod.Get, SecurityHarness.AnonymousPath)));
        _forwarded = harness.Origin.LastRequestTo(SecurityHarness.AnonymousPath);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_forward_the_request() => Assert.NotNull(_forwarded);

    [Fact]
    public void should_not_relay_the_connection_header() => Assert.False(_forwarded!.Has("Connection"));

    [Fact]
    public void should_not_relay_the_keep_alive_header() => Assert.False(_forwarded!.Has("Keep-Alive"));

    [Fact]
    public void should_not_relay_the_proxy_connection_header() => Assert.False(_forwarded!.Has("Proxy-Connection"));

    [Fact]
    public void should_not_relay_the_upgrade_header() => Assert.False(_forwarded!.Has("Upgrade"));

    [Fact]
    public void should_not_relay_the_te_header() => Assert.False(_forwarded!.Has("TE"));

    [Fact]
    public void should_not_relay_the_transfer_encoding_header() => Assert.False(_forwarded!.Has("Transfer-Encoding"));

    /// <summary>
    /// Records the one deviation: RFC 9110 section 7.6.1 also asks an intermediary to drop every field the
    /// <c>Connection</c> header <em>names</em>, and this one survives — the connection-token list is not
    /// parsed, only the standard hop-by-hop set is stripped.
    /// </summary>
    /// <remarks>
    /// Pinned rather than left unasserted, because it is a real deviation and a change in either direction
    /// should be a deliberate one. It is not exploitable: the mechanism only ever <em>removes</em> headers,
    /// so ignoring it forwards more than was asked rather than less, and the surviving header is one the
    /// same attacker already chose to send. The direction that would matter — naming a trusted hop's
    /// identity headers in <c>Connection</c> to have them stripped — is closed by the <c>Connection</c>
    /// header itself never being relayed.
    /// </remarks>
    [Fact]
    public void should_not_honor_the_connection_token_list_for_a_named_custom_header() =>
        Assert.Equal("leaked", _forwarded!.Value("X-Custom-Hop"));

    static HttpRequestMessage HopByHop(HttpRequestMessage request)
    {
        request.Headers.TryAddWithoutValidation("Connection", "close, X-Custom-Hop");
        request.Headers.TryAddWithoutValidation("Keep-Alive", "timeout=5");
        request.Headers.TryAddWithoutValidation("Proxy-Connection", "keep-alive");
        request.Headers.TryAddWithoutValidation("Upgrade", "websocket");
        request.Headers.TryAddWithoutValidation("TE", "trailers");
        request.Headers.TryAddWithoutValidation("Transfer-Encoding", "chunked");
        request.Headers.TryAddWithoutValidation("X-Custom-Hop", "leaked");

        return request;
    }
}
