// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_TrustedProxies.when_a_spoofed_scheme_reaches_the_logout_origin;

/// <summary>
/// The same request from the deployment's own ingress is honored, which is what proves the refusal next to it
/// is a decision about the caller rather than a redirect that never worked.
/// <para>
/// A deployment terminating TLS at its ingress genuinely is served over <c>https</c>, and its logout has to
/// be able to return there. This is the case that would break if the boundary were drawn by refusing every
/// forwarded scheme rather than by asking who sent it.
/// </para>
/// </summary>
/// <param name="harness">The running proxy, its origin, and the record of what each request was normalized to.</param>
[Collection(TrustedProxySpecCollection.Name)]
public class and_the_peer_is_trusted(TrustedProxyHarness harness) : IAsyncLifetime
{
    string? _location;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();

        var request = TrustedProxyHarness.From(
            TrustedProxyHarness.TrustedPeer,
            $"{WellKnownPaths.Logout}?redirect={Uri.EscapeDataString(and_the_peer_is_not_trusted.Target)}");
        request.Headers.TryAddWithoutValidation("X-Forwarded-Proto", "https");

        using var response = await client.SendAsync(request);

        _location = response.Headers.Location?.ToString();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void should_redirect_to_the_declared_origin() =>
        Assert.Equal(and_the_peer_is_not_trusted.Target, _location);
}
