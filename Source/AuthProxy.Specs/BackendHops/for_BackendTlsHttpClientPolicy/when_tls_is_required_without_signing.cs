// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net.Security;

namespace Cratis.AuthProxy.BackendHops.for_BackendTlsHttpClientPolicy;

public class when_tls_is_required_without_signing : given.a_tls_policy
{
    void Establish()
    {
        configuration.BackendTls.RequireTlsOnIdentityHops = true;
        configuration.Invite = new() { ExchangeUrl = "https://exchange.example/invite" };
        configuration.SignIn = new() { NotifyUrl = "https://notify.example/signin" };
        configuration.TenantVerification = new() { UrlTemplate = "https://verify.example/tenants/{tenantId}" };
    }

    [Theory]
    [InlineData("frontend.example")]
    [InlineData("exchange.example")]
    [InlineData("notify.example")]
    [InlineData("verify.example")]
    public void should_apply_the_backend_tls_policy(string host)
    {
        using var server = certificates.Issue(host: host);
        policy.ValidateServerCertificate(host, server, null, SslPolicyErrors.RemoteCertificateChainErrors).ShouldBeTrue();
        policy.SelectClientCertificate(host).ShouldNotBeNull();
    }

    [Fact] void should_not_extend_trust_to_unrelated_hosts() => policy.SelectClientCertificate("unrelated.example").ShouldBeNull();
}
