// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_TrustedProxies.when_a_spoofed_scheme_reaches_the_logout_origin;

/// <summary>
/// OWASP A01 — Broken Access Control (open redirect). A caller must not be able to widen the post-logout
/// allow-list by naming the scheme the proxy thinks it is served over.
/// <para>
/// The allow-list admits the proxy's own public origin, built from <c>Request.Scheme</c> and
/// <c>Request.Host</c>. A caller that could set the scheme would add a second origin to that list — the same
/// host under the other scheme — and the logout endpoint would then redirect to it. The target chosen here is
/// exactly that: the same host, the other scheme, and nothing else about the deployment changed.
/// </para>
/// </summary>
/// <param name="harness">The running proxy, its origin, and the record of what each request was normalized to.</param>
[Collection(TrustedProxySpecCollection.Name)]
public class and_the_peer_is_not_trusted(TrustedProxyHarness harness) : IAsyncLifetime
{
    /// <summary>The same host as the proxy, under the scheme a spoofed header would claim.</summary>
    public const string Target = "https://localhost/after-logout";

    string? _location;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();

        var request = TrustedProxyHarness.From(
            TrustedProxyHarness.UntrustedPeer,
            $"{WellKnownPaths.Logout}?redirect={Uri.EscapeDataString(Target)}");
        request.Headers.TryAddWithoutValidation("X-Forwarded-Proto", "https");

        using var response = await client.SendAsync(request);

        _location = response.Headers.Location?.ToString();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void should_fall_back_to_the_application_root() =>
        Assert.Equal(PostLogoutRedirectPolicy.ApplicationRoot, _location);

    [Fact]
    public void should_not_redirect_to_the_origin_the_caller_conjured() =>
        Assert.NotEqual(Target, _location);
}
