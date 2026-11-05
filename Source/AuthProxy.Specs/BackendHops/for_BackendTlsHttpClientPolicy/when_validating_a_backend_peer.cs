// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net.Security;

namespace Cratis.AuthProxy.BackendHops.for_BackendTlsHttpClientPolicy;

public class when_validating_a_backend_peer : given.a_tls_policy
{
    bool _accepted;
    void Because()
    {
        using var server = certificates.Issue();
        _accepted = policy.ValidateServerCertificate("localhost", server, null, SslPolicyErrors.RemoteCertificateChainErrors);
    }
    [Fact] void should_accept_the_custom_authority() => _accepted.ShouldBeTrue();
    [Fact] void should_select_the_client_identity_for_the_backend() => policy.SelectClientCertificate("localhost")!.HasPrivateKey.ShouldBeTrue();
    [Fact] void should_not_offer_the_client_identity_to_a_frontend() => policy.SelectClientCertificate("frontend.example").ShouldBeNull();
    [Fact] void should_not_offer_the_client_identity_to_an_identity_provider() => policy.SelectClientCertificate("identity.example").ShouldBeNull();

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public void should_apply_backend_tls_to_frontends_only_when_signed(bool backend, bool signingEnabled)
    {
        configuration.Services["app"].Backend = backend ? new() { BaseUrl = "https://localhost" } : null;
        configuration.Services["app"].ForwardedIdentity = signingEnabled ? new() : null;
        using var server = certificates.Issue(host: "frontend.example");
        policy.ValidateServerCertificate("frontend.example", server, null, SslPolicyErrors.RemoteCertificateChainErrors).ShouldEqual(signingEnabled);
        (policy.SelectClientCertificate("frontend.example") is not null).ShouldEqual(signingEnabled);
    }
}
