// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_BackendTls;

public class when_the_backend_presents_a_trusted_certificate
{
    [Fact]
    public async Task should_present_the_client_identity_on_every_identity_bearing_flow()
    {
        using var certificates = new HopCertificates();
        using var server = certificates.Issue();
        await using var proxy = new BackendTlsHarness(certificates, new(server));
        using var client = proxy.CreateSecurityClient();
        using var request = ForwardedIdentityHarness.Session(ForwardedIdentityHarness.SignedHost, "/private");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(certificates.ClientThumbprint, proxy.ApplicationOrigin.Received.Single(observed => observed.RawTarget.EndsWith("/private", StringComparison.Ordinal)).ClientCertificateThumbprint);
        Assert.Equal(certificates.ClientThumbprint, proxy.ApplicationOrigin.Received.Single(observed => observed.RawTarget.EndsWith(WellKnownPaths.IdentityDetails, StringComparison.Ordinal)).ClientCertificateThumbprint);

        using var selection = ForwardedIdentityHarness.Session(ForwardedIdentityHarness.SignedHost, WellKnownPaths.SelectTenant + "?tenantId=11111111-1111-1111-1111-111111111111");
        using var selected = await client.SendAsync(selection, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, selected.StatusCode);
        Assert.Equal(certificates.ClientThumbprint, proxy.Tenants.Received.Last().ClientCertificateThumbprint);

        using var bearer = BearerRouteHarness.WithToken(HttpMethod.Post, BearerRouteHarness.RoutePrefix + "/tools", proxy.Issuer.Token());
        bearer.Headers.Host = ForwardedIdentityHarness.SignedHost;
        using var forwarded = await client.SendAsync(bearer, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, forwarded.StatusCode);
        Assert.Equal(certificates.ClientThumbprint, proxy.ApplicationOrigin.Received.Last().ClientCertificateThumbprint);
    }
}
