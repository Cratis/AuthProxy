// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net.Security;

namespace Cratis.AuthProxy.BackendHops.for_BackendTlsHttpClientPolicy;

public class when_refusing_an_unauthenticated_peer : given.a_tls_policy
{
    [Theory]
    [InlineData("wrong-name")]
    [InlineData("expired")]
    [InlineData("wrong-authority")]
    [InlineData("wrong-eku")]
    [InlineData("missing")]
    [InlineData("non-backend")]
    [InlineData("system-trust")]
    public void should_not_relax_peer_authentication(string scenario)
    {
        using var other = new given.TestCertificates();
        using var server = scenario == "wrong-authority" ? other.Issue() : certificates.Issue(client: scenario == "wrong-eku", expired: scenario == "expired");
        if (scenario == "system-trust") configuration.BackendTls.TrustedCertificateAuthoritiesPath = string.Empty;
        var errors = scenario switch
        {
            "wrong-name" => SslPolicyErrors.RemoteCertificateNameMismatch,
            "missing" => SslPolicyErrors.RemoteCertificateNotAvailable,
            _ => SslPolicyErrors.RemoteCertificateChainErrors
        };
        policy.ValidateServerCertificate(scenario == "non-backend" ? "frontend.example" : "localhost", scenario == "missing" ? null : server, null, errors).ShouldBeFalse();
    }
}
