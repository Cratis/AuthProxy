// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Creates <c language="text">private_key_jwt</c> client assertions (RFC 7523, OpenID Connect Core section 9) signed with a
/// certificate.
/// </summary>
static class CertificateClientAssertion
{
    const string RsaKeyAlgorithm = "1.2.840.113549.1.1.1";

    /// <summary>
    /// The lifetime of each assertion. It is presented once, immediately, so it only needs to survive clock skew.
    /// </summary>
    internal static TimeSpan Lifetime { get; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Creates a signed client assertion.
    /// </summary>
    /// <param name="certificate">The certificate whose private key signs the assertion.</param>
    /// <param name="clientId">The client ID, used as issuer and subject.</param>
    /// <param name="audience">The endpoint the assertion is presented to.</param>
    /// <param name="now">The current time.</param>
    /// <returns>The serialized assertion.</returns>
    /// <exception cref="OidcClientCredentialUnavailable">The certificate has no usable private key.</exception>
    internal static string Create(X509Certificate2 certificate, string clientId, string audience, DateTimeOffset now)
    {
        using var ecKey = certificate.HasPrivateKey ? certificate.GetECDsaPrivateKey() : null;
        var signingCredentials = SigningCredentialsFor(certificate, ecKey);
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = clientId,
            Audience = audience,
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = now.Add(Lifetime).UtcDateTime,
            Claims = new Dictionary<string, object>
            {
                [JwtRegisteredClaimNames.Sub] = clientId,
                [JwtRegisteredClaimNames.Jti] = Guid.NewGuid().ToString()
            },
            SigningCredentials = signingCredentials
        };
        var handler = new JwtSecurityTokenHandler { SetDefaultTimesOnTokenCreation = false };
        var token = handler.CreateJwtSecurityToken(descriptor);
        if (ecKey is not null)
        {
            token.Header[JwtHeaderParameterNames.X5t] = Base64UrlEncoder.Encode(certificate.GetCertHash());
        }

        return handler.WriteToken(token);
    }

    static SigningCredentials SigningCredentialsFor(X509Certificate2 certificate, ECDsa? ecKey)
    {
        if (ecKey is not null)
        {
            var algorithm = ecKey.KeySize switch
            {
                256 => SecurityAlgorithms.EcdsaSha256,
                384 => SecurityAlgorithms.EcdsaSha384,
                521 => SecurityAlgorithms.EcdsaSha512,
                _ => throw new OidcClientCredentialUnavailable($"The client certificate '{certificate.Subject}' has an unsupported ECDSA key size.")
            };
            var key = new ECDsaSecurityKey(ecKey)
            {
                KeyId = certificate.Thumbprint,

                // The private-key handle belongs to this call, not to the signature-provider cache.
                CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
            };

            return new SigningCredentials(key, algorithm);
        }

        return certificate.HasPrivateKey && certificate.PublicKey.Oid.Value == RsaKeyAlgorithm
            ? new X509SigningCredentials(certificate, SecurityAlgorithms.RsaSha256)
            : throw new OidcClientCredentialUnavailable(
                $"The client certificate '{certificate.Subject}' has no RSA or ECDSA private key to sign a client assertion with.");
    }
}
