// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_CanonicalIdentityConfigurationValidator.given;

public class a_valid_authentication_configuration : Specification
{
    protected C.Authentication _authentication;
    protected ValidateOptionsResult _result;

    void Establish() => _authentication = new C.Authentication
    {
        OidcProviders = [OidcProvider("Entra", "entra")],
        OAuthProviders = [OAuthProvider("GitHub", "github")]
    };

    protected static C.OidcProvider OidcProvider(string name, string providerKey) => new()
    {
        Name = name,
        CanonicalIdentity = new C.CanonicalIdentity { ProviderKey = providerKey, SubjectClaimType = "sub" }
    };

    protected static C.OAuthProvider OAuthProvider(string name, string providerKey) => new()
    {
        Name = name,
        CanonicalIdentity = new C.CanonicalIdentity
        {
            ProviderKey = providerKey,
            SubjectClaimType = "id",
            Issuer = "https://github.example.com"
        }
    };

    protected void Validate() => _result = new CanonicalIdentityConfigurationValidator().Validate(null, _authentication);
}
