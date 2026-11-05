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
}
