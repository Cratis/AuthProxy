// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_OidcClientCredentialConfigurationValidator;

public class when_a_certificate_store_credential_names_no_thumbprint : given.an_oidc_client_credential_validator
{
    void Establish() => _provider.ClientCredential!.Source = C.OidcClientCredentialSource.CertificateStore;

    void Because() => Validate();

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_the_missing_thumbprint() => _result.FailureMessage.ShouldContain("CertificateThumbprint");
}
