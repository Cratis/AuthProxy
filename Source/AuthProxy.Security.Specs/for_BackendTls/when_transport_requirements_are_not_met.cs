// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Options;

namespace Cratis.AuthProxy.Security.for_BackendTls;

public class when_transport_requirements_are_not_met
{
    [Theory]
    [InlineData(true, "Backend:BaseUrl")]
    [InlineData(false, "BackendTls:ClientCertificate")]
    public void should_refuse_startup_before_sending_identity(bool http, string key)
    {
        using var certificates = new HopCertificates();
        using var server = certificates.Issue();
        using var proxy = new BackendTlsHarness(certificates, http ? null : new(server), client: http);
        var exception = Assert.Throws<OptionsValidationException>(proxy.CreateSecurityClient);
        Assert.Contains(key, exception.Message, StringComparison.Ordinal);
        Assert.Empty(proxy.ApplicationOrigin.Received);
    }

    [Fact]
    public async Task should_allow_explicit_local_development_over_http()
    {
        using var certificates = new HopCertificates();
        await using var proxy = new BackendTlsHarness(certificates, null, local: true, client: false);
        using var client = proxy.CreateSecurityClient();
        using var request = ForwardedIdentityHarness.Session(ForwardedIdentityHarness.SignedHost, "/private");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.True(response.IsSuccessStatusCode);
        Assert.NotEmpty(proxy.ApplicationOrigin.Received);
    }
}
