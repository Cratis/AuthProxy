// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Invites;

/// <summary>
/// Generates RSA key pairs and signed JWT tokens for use in specifications.
/// </summary>
static class TokenFixture
{
    /// <summary>
    /// Creates an RSA key pair and returns the private key as a <see cref="RsaSecurityKey"/>
    /// and the public key as a PEM string.
    /// </summary>
    /// <returns>A tuple of the RSA private key and the PEM-encoded public key.</returns>
    public static (RsaSecurityKey PrivateKey, string PublicKeyPem) GenerateKeyPair()
    {
        var rsa = RSA.Create(2048);
        var privateKey = new RsaSecurityKey(rsa);
        var publicKeyPem = rsa.ExportSubjectPublicKeyInfoPem();
        return (privateKey, publicKeyPem);
    }

    /// <summary>
    /// Creates a signed JWT token using the given key and parameters.
    /// </summary>
    /// <param name="signingKey">The RSA private key used to sign the token.</param>
    /// <param name="issuer">The token issuer claim value.</param>
    /// <param name="audience">The token audience claim value.</param>
    /// <param name="expires">The token expiry time; defaults to one hour from now.</param>
    /// <param name="notBefore">The earliest time the token is valid; defaults to one minute ago.</param>
    /// <param name="additionalClaims">Optional additional claims to include in the token.</param>
    /// <returns>The compact-serialized signed JWT string.</returns>
    public static string CreateToken(
        RsaSecurityKey signingKey,
        string issuer = "test-issuer",
        string audience = "test-audience",
        DateTime? expires = null,
        DateTime? notBefore = null,
        IEnumerable<Claim>? additionalClaims = null)
    {
        var handler = new JsonWebTokenHandler();
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            Expires = expires ?? DateTime.UtcNow.AddHours(1),
            NotBefore = notBefore ?? DateTime.UtcNow.AddMinutes(-1),
            SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256),
            Claims = additionalClaims?.ToDictionary(c => c.Type, c => (object)c.Value),
        };
        return handler.CreateToken(descriptor);
    }
}
