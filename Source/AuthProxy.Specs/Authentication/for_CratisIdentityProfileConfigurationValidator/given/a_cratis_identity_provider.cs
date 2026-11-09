// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_CratisIdentityProfileConfigurationValidator.given;

public class a_cratis_identity_provider : Specification
{
    protected C.OidcProvider _provider;
    protected C.AuthProxy _configuration;
    protected ValidateOptionsResult _result;

    void Establish()
    {
        _provider = new C.OidcProvider
        {
            Name = "Cratis Identity",
            Type = C.OidcProviderType.CratisIdentity,
            Authority = "https://identity.cratis.example/realms/products",
            ClientId = "studio-web",
            ClientSecret = "configured-client-secret-value",
        };
        _configuration = new C.AuthProxy { Authentication = new C.Authentication { OidcProviders = [_provider] } };
    }

    protected void Validate() => _result = new CratisIdentityProfileConfigurationValidator().Validate(null, _configuration);
}
