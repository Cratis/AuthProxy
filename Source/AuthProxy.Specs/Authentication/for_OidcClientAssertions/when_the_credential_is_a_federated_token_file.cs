// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Authentication.for_OidcClientAssertions;

public class when_the_credential_is_a_federated_token_file : given.oidc_client_assertions
{
    string _federatedToken;
    string _assertion;

    void Establish()
    {
        // The platform's token is opaque to AuthProxy: it is read, never re-signed, so any well-formed JWT will do.
        _federatedToken = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "https://oidc.prod-aks.azure.com/cluster",
            Audience = "api://AzureADTokenExchange",
            Subject = new ClaimsIdentity([new Claim("sub", "system:serviceaccount:default:authproxy")]),
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(new byte[32]), SecurityAlgorithms.HmacSha256)
        });

        var path = Path.Combine(_directory, "azure-identity-token");
        File.WriteAllText(path, _federatedToken);
        _provider.ClientCredential!.Source = C.OidcClientCredentialSource.FederatedTokenFile;
        _provider.ClientCredential.TokenFilePath = path;
    }

    async Task Because() => _assertion = await _assertions.Create(Scheme, _provider, TokenEndpoint, CancellationToken.None);

    [Fact] void should_present_the_platform_token_as_the_assertion() => _assertion.ShouldEqual(_federatedToken);
}
