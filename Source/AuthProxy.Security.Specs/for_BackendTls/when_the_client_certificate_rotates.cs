// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.BackendHops;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Security.for_BackendTls;

public class when_the_client_certificate_rotates
{
    [Fact]
    public async Task should_use_the_new_client_on_new_connections_without_restarting()
    {
        using var certificates = new HopCertificates();
        using var server = certificates.Issue();
        await using var proxy = new BackendTlsHarness(certificates, new(server));
        using var client = proxy.CreateSecurityClient();
        using var first = ForwardedIdentityHarness.Session(ForwardedIdentityHarness.SignedHost, "/private");
        using var firstResponse = await client.SendAsync(first, TestContext.Current.CancellationToken);
        Assert.True(firstResponse.IsSuccessStatusCode);
        var original = certificates.ClientThumbprint;
        var firstConnection = proxy.ApplicationOrigin.Received.Last(request => request.RawTarget.EndsWith("/private", StringComparison.Ordinal));
        Assert.Equal(original, firstConnection.ClientCertificateThumbprint);
        certificates.RotateClient();
        Assert.True(proxy.Services.GetRequiredService<IBackendTlsMaterialSource>().TryReload());

        // Reload changes handshake material, not existing connections. Let the production pool
        // lifetime elapse so the same client must establish a new TLS connection.
        await Task.Delay(C.BackendTls.MinimumReloadInterval + TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);
        using var second = ForwardedIdentityHarness.Session(ForwardedIdentityHarness.SignedHost, "/private?rotated=1");
        using var secondResponse = await client.SendAsync(second, TestContext.Current.CancellationToken);
        Assert.True(secondResponse.IsSuccessStatusCode);
        var observed = proxy.ApplicationOrigin.Received.Last(request => request.RawTarget.Contains("rotated=1", StringComparison.Ordinal));
        Assert.NotEqual(firstConnection.ConnectionId, observed.ConnectionId);
        Assert.Equal(certificates.ClientThumbprint, observed.ClientCertificateThumbprint);
        Assert.NotEqual(original, observed.ClientCertificateThumbprint);
    }
}
