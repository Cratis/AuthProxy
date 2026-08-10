// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_TrustedProxies;

/// <summary>
/// OWASP A05 — Security Misconfiguration. A caller that is not one of the deployment's own proxies must not
/// be able to say where it is or how it got here.
/// <para>
/// <c>X-Forwarded-For</c> and <c>X-Forwarded-Proto</c> are ordinary request headers, and until a boundary is
/// declared they are believed from anyone who can open a connection. The address is what gets written into
/// the audit record of a sign-in; the scheme is what decides whether eleven session cookies carry
/// <c>Secure</c>, what the OIDC <c>post_logout_redirect_uri</c> claims the proxy's public origin to be, and
/// which origins the post-logout allow-list admits. All of that is settled by two values, so the two values
/// are what this asserts on.
/// </para>
/// </summary>
/// <param name="harness">The running proxy, its origin, and the record of what each request was normalized to.</param>
[Collection(TrustedProxySpecCollection.Name)]
public class when_forwarded_headers_come_from_an_untrusted_peer(TrustedProxyHarness harness) : IAsyncLifetime
{
    ObservedRequest? _observed;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();

        var request = TrustedProxyHarness.From(TrustedProxyHarness.UntrustedPeer, TrustedProxyHarness.AnonymousPath);
        request.Headers.TryAddWithoutValidation("X-Forwarded-For", "203.0.113.7, 10.0.0.1");
        request.Headers.TryAddWithoutValidation("X-Forwarded-Proto", "https");

        await client.SendAsync(request);

        _observed = harness.Observations.Last;
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_have_observed_the_request() => Assert.NotNull(_observed);

    [Fact]
    public void should_keep_the_address_the_connection_actually_came_from() =>
        Assert.Equal(TrustedProxyHarness.UntrustedPeer, _observed!.RemoteIpAddress);

    /// <summary>
    /// Both entries are asserted against, because the two ends of the chain are what the two halves of the
    /// original defect each handed out: the middleware would have taken the right-most, and the sign-in
    /// resolver read the left-most straight off the header.
    /// </summary>
    [Fact]
    public void should_not_take_the_rightmost_address_the_caller_wrote() =>
        Assert.NotEqual("10.0.0.1", _observed!.RemoteIpAddress);

    /// <inheritdoc cref="should_not_take_the_rightmost_address_the_caller_wrote"/>
    [Fact]
    public void should_not_take_the_leftmost_address_the_caller_wrote() =>
        Assert.NotEqual("203.0.113.7", _observed!.RemoteIpAddress);

    [Fact]
    public void should_keep_the_real_transport_scheme() =>
        Assert.Equal("http", _observed!.Scheme);
}
