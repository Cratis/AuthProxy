// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_OidcClientCredentialConfigurationValidator;

public class when_no_client_credential_is_configured : given.an_oidc_client_credential_validator
{
    void Establish()
    {
        _provider.ClientCredential = null;
        _provider.ClientSecret = "client-secret";
    }

    void Because() => Validate();

    [Fact] void should_succeed() => _result.Succeeded.ShouldBeTrue();
}
