// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_BackendTls;

public class when_the_backend_certificate_is_not_authenticated
{
    [Theory]
    [InlineData("wrong-ca")]
    [InlineData("expired")]
    [InlineData("wrong-name")]
    public async Task should_never_deliver_forwarded_identity_to_the_origin(string problem)
    {
        using var certificates = new HopCertificates();
        using var other = new HopCertificates();
        using var server = problem == "wrong-ca" ? other.Issue() : certificates.Issue(expired: problem == "expired", host: problem == "wrong-name" ? "backend.test" : "localhost");
        await using var proxy = new BackendTlsHarness(certificates, new(server));
        using var client = proxy.CreateSecurityClient();
        using var request = ForwardedIdentityHarness.Session(ForwardedIdentityHarness.SignedHost, "/private");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.False(response.IsSuccessStatusCode);
        Assert.Empty(proxy.ApplicationOrigin.Received);
        Assert.Empty(proxy.Tenants.Received);
    }

    [Fact]
    public async Task should_refuse_the_signed_tenant_list_when_its_tls_peer_is_unknown()
    {
        using var certificates = new HopCertificates();
        using var other = new HopCertificates();
        using var server = other.Issue();
        await using var proxy = new BackendTlsHarness(certificates, new(server));
        using var client = proxy.CreateSecurityClient();
        using var request = ForwardedIdentityHarness.Session(ForwardedIdentityHarness.SignedHost, WellKnownPaths.SelectTenant + "?tenantId=11111111-1111-1111-1111-111111111111");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Empty(proxy.Tenants.Received);
    }
}
