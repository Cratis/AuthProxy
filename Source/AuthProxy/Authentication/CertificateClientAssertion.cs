// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Creates <c language="text">private_key_jwt</c> client assertions (RFC 7523, OpenID Connect Core section 9) signed with a
/// certificate.
/// </summary>
static class CertificateClientAssertion
{
    const string RsaKeyAlgorithm = "1.2.840.113549.1.1.1";
    const string EcKeyAlgorithm = "1.2.840.10045.2.1";

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
        var signingCredentials = SigningCredentialsFor(certificate);
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

        return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(descriptor);
    }

    static X509SigningCredentials SigningCredentialsFor(X509Certificate2 certificate) => (certificate.HasPrivateKey, certificate.PublicKey.Oid.Value) switch
    {
        (true, RsaKeyAlgorithm) => new X509SigningCredentials(certificate, SecurityAlgorithms.RsaSha256),
        (true, EcKeyAlgorithm) => new X509SigningCredentials(certificate, SecurityAlgorithms.EcdsaSha256),
        _ => throw new OidcClientCredentialUnavailable(
            $"The client certificate '{certificate.Subject}' has no RSA or ECDSA private key to sign a client assertion with.")
    };
}
