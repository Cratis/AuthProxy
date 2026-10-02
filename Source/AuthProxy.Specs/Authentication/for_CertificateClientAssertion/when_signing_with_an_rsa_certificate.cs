// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography.X509Certificates;
using Cratis.AuthProxy.Authentication.given;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Authentication.for_CertificateClientAssertion;

public class when_signing_with_an_rsa_certificate : Specification
{
    const string ClientId = "client-id";
    const string TokenEndpoint = "https://login.example.com/tenant/oauth2/v2.0/token";

    X509Certificate2 _certificate;
    DateTimeOffset _now;
    JsonWebToken _assertion;
    TokenValidationResult _validation;

    void Establish()
    {
        _certificate = ClientCertificates.Rsa();
        _now = DateTimeOffset.UtcNow;
    }

    async Task Because()
    {
        var serialized = CertificateClientAssertion.Create(_certificate, ClientId, TokenEndpoint, _now);
        _assertion = new JsonWebToken(serialized);
        _validation = await new JsonWebTokenHandler().ValidateTokenAsync(serialized, new TokenValidationParameters
        {
            ValidIssuer = ClientId,
            ValidAudience = TokenEndpoint,
            IssuerSigningKey = new X509SecurityKey(_certificate)
        });
    }

    void Destroy() => _certificate.Dispose();

    [Fact] void should_carry_a_signature_the_certificate_verifies() => _validation.IsValid.ShouldBeTrue();
    [Fact] void should_sign_with_rs256() => _assertion.Alg.ShouldEqual(SecurityAlgorithms.RsaSha256);
    [Fact] void should_be_issued_by_the_client() => _assertion.Issuer.ShouldEqual(ClientId);
    [Fact] void should_be_about_the_client() => _assertion.Subject.ShouldEqual(ClientId);
    [Fact] void should_be_addressed_to_the_token_endpoint() => _assertion.Audiences.ShouldContainOnly(TokenEndpoint);
    [Fact] void should_carry_a_unique_identifier() => string.IsNullOrEmpty(_assertion.Id).ShouldBeFalse();
    [Fact] void should_name_the_certificate_by_thumbprint() => _assertion.X5t.ShouldEqual(Base64UrlEncoder.Encode(_certificate.GetCertHash()));
    [Fact] void should_expire_shortly() => (_assertion.ValidTo - _assertion.IssuedAt).ShouldEqual(CertificateClientAssertion.Lifetime);
}
