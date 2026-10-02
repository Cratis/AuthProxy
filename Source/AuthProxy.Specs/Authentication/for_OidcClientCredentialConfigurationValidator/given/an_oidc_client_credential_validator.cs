// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_OidcClientCredentialConfigurationValidator.given;

public class an_oidc_client_credential_validator : Specification
{
    protected Dictionary<string, string> _environment;
    protected C.OidcProvider _provider;
    protected OidcClientCredentialConfigurationValidator _validator;
    protected ValidateOptionsResult _result;

    void Establish()
    {
        _environment = [];
        _provider = new()
        {
            Name = "Workforce",
            Authority = "https://login.microsoftonline.com/tenant/v2.0",
            ClientId = "client-id",
            ClientCredential = new()
        };
        _validator = new(_ => _environment.GetValueOrDefault(_));
    }

    protected void Validate() => _result = _validator.Validate(null, new C.Authentication { OidcProviders = [_provider] });
}
