// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_OidcClientCredentialConfigurationValidator;

public class when_a_key_vault_credential_is_not_reached_over_https : given.an_oidc_client_credential_validator
{
    void Establish()
    {
        _provider.ClientCredential!.Source = C.OidcClientCredentialSource.KeyVaultCertificate;
        _provider.ClientCredential.KeyVaultUrl = "http://contoso.vault.azure.net";
        _provider.ClientCredential.KeyVaultCertificateName = "authproxy";
    }

    void Because() => Validate();

    [Fact] void should_fail() => _result.Failed.ShouldBeTrue();
    [Fact] void should_name_the_vault_url() => _result.FailureMessage.ShouldContain("KeyVaultUrl");
}
