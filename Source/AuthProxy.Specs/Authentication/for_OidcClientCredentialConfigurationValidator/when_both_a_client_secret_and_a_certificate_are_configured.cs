// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_OidcClientCredentialConfigurationValidator;

public class when_both_a_client_secret_and_a_certificate_are_configured : given.an_oidc_client_credential_validator
{
    void Establish()
    {
        _provider.ClientSecret = "client-secret";
        _provider.ClientCredential!.Source = C.OidcClientCredentialSource.CertificateFile;
        _provider.ClientCredential.CertificatePath = "/certificates/client.pfx";
    }

    void Because() => Validate();

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_both_credentials() => _result.FailureMessage.ShouldContain("ClientSecret and a CertificateFile ClientCredential");
}
