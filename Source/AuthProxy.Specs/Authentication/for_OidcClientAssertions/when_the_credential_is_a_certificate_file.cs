// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography.X509Certificates;
using Cratis.AuthProxy.Authentication.given;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Authentication.for_OidcClientAssertions;

public class when_the_credential_is_a_certificate_file : given.oidc_client_assertions
{
    X509Certificate2 _certificate;
    string _assertion;
    TokenValidationResult _validation;

    void Establish()
    {
        _certificate = ClientCertificates.Rsa();
        var path = Path.Combine(_directory, "client.pfx");
        File.WriteAllBytes(path, _certificate.Export(X509ContentType.Pfx, "certificate-password"));
        _provider.ClientCredential!.Source = C.OidcClientCredentialSource.CertificateFile;
        _provider.ClientCredential.CertificatePath = path;
        _provider.ClientCredential.CertificatePassword = "certificate-password";
    }

    async Task Because()
    {
        _assertion = await _assertions.Create(Scheme, _provider, TokenEndpoint, CancellationToken.None);
        _validation = await new JsonWebTokenHandler().ValidateTokenAsync(_assertion, new TokenValidationParameters
        {
            ValidIssuer = _provider.ClientId,
            ValidAudience = TokenEndpoint,
            IssuerSigningKey = new X509SecurityKey(_certificate)
        });
    }

    void Destroy() => _certificate.Dispose();

    [Fact] void should_sign_the_assertion_with_the_certificate_from_the_file() => _validation.IsValid.ShouldBeTrue();
    [Fact] void should_address_the_assertion_to_the_token_endpoint() => new JsonWebToken(_assertion).Audiences.ShouldContainOnly(TokenEndpoint);
}
