// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Authentication.for_CertificateClientAssertion;

public class when_signing_with_an_ecdsa_certificate : Specification
{
    readonly List<TokenValidationResult> _validations = [];
    readonly List<string> _algorithms = [];
    readonly List<string> _thumbprints = [];
    readonly List<string> _expectedThumbprints = [];

    async Task Because()
    {
        foreach (var curve in new[] { ECCurve.NamedCurves.nistP256, ECCurve.NamedCurves.nistP384, ECCurve.NamedCurves.nistP521 })
        {
            using var key = ECDsa.Create(curve);
            var request = new CertificateRequest("CN=authproxy-client", key, HashAlgorithmName.SHA256);
            using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
            using var publicKey = certificate.GetECDsaPublicKey();

            // Repeated signing also verifies that disposing one signing-key handle does not poison a cached provider.
            for (var index = 0; index < 2; index++)
            {
                var serialized = CertificateClientAssertion.Create(certificate, "client-id", "https://login.example.com/token", DateTimeOffset.UtcNow);
                var assertion = new JsonWebToken(serialized);
                _algorithms.Add(assertion.Alg);
                _thumbprints.Add(assertion.X5t);
                _expectedThumbprints.Add(Base64UrlEncoder.Encode(certificate.GetCertHash()));
                _validations.Add(await new JsonWebTokenHandler().ValidateTokenAsync(serialized, new TokenValidationParameters
                {
                    ValidIssuer = "client-id",
                    ValidAudience = "https://login.example.com/token",
                    IssuerSigningKey = new ECDsaSecurityKey(publicKey)
                    {
                        CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
                    }
                }));
            }
        }
    }

    [Fact] void should_carry_signatures_the_certificates_verify() => _validations.TrueForAll(_ => _.IsValid).ShouldBeTrue();
    [Fact] void should_select_the_algorithm_for_each_curve() => _algorithms.ShouldEqual(new[] { "ES256", "ES256", "ES384", "ES384", "ES512", "ES512" });
    [Fact] void should_preserve_the_certificate_thumbprints() => _thumbprints.ShouldEqual(_expectedThumbprints);
}
