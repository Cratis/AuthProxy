// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography.X509Certificates;
using Cratis.AuthProxy.Authentication.given;

namespace Cratis.AuthProxy.Authentication.for_CertificateClientAssertion;

public class when_the_certificate_has_no_private_key : Specification
{
    X509Certificate2 _certificate;
    Exception _error;

    void Establish()
    {
        using var withKey = ClientCertificates.Rsa();
        _certificate = X509CertificateLoader.LoadCertificate(withKey.Export(X509ContentType.Cert));
    }

    void Because() => _error = Catch.Exception(() => CertificateClientAssertion.Create(_certificate, "client-id", "https://login.example.com/token", DateTimeOffset.UtcNow));

    void Destroy() => _certificate.Dispose();

    [Fact] void should_refuse_to_sign() => _error.ShouldBeOfExactType<OidcClientCredentialUnavailable>();
}
